using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.Caching;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Ae.Dns.Client;
using Ae.Dns.Protocol;
using Ae.Dns.Protocol.Enums;
using Ae.Dns.Protocol.Records;
using PCL.Core.IO.Net.Http;
using PCL.Core.Logging;

namespace PCL.Core.IO.Net.Dns;

public class DnsQuery : IDisposable
{
    private const string ModuleName = "DoH query";
    public static DnsQuery Instance { get; } = new();

    private readonly DnsCachingClient _resolver;
    private readonly HttpClient[] _httpClients;

    /// <summary>
    ///     JSON 形式的 DoH 端点。当二进制 DoH 返回污染结果时，用它重新查询。
    /// </summary>
    private static readonly string[] JsonDohServers =
    [
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/resolve"
    ];

    /// <summary>
    ///     已知的 DNS 污染（投毒）地址前缀。命中这些地址时连接必然超时，应视为解析失败重新查询。
    /// </summary>
    private static readonly string[] SuspiciousPrefixes =
    [
        "31.13.", "66.220.", "69.171.", "173.252.", "204.15.20.", // Facebook
        "162.125.", // Dropbox
        "4.36.66.", "8.7.198.", "37.61.54.", "46.82.174.", "59.24.3.", "64.33.", "64.66.163.",
        "65.104.202.", "65.160.219.", "66.45.252.", "72.14.205.", "78.16.49.", "93.46.8.89",
        "128.121.126.", "128.242.240.", "159.106.121.", "169.132.13.", "188.5.4.", "189.163.17.", "192.67.198.",
        "197.4.4.", "199.59.148.", "199.59.149.", "199.59.150.", "199.59.151.",
        "202.106.1.", "203.98.7.", "207.123.56.", "243.185.187.", "249.129.46.",
        "253.157.14.",
        "2a03:2880:" // Facebook IPv6
    ];

    private readonly HttpClient _jsonClient;

    // JSON DoH 结果缓存，避免每次连接都重复查询
    private readonly ConcurrentDictionary<string, (IPAddress[] Addresses, DateTime ExpireAt)> _jsonCache = new();

    /// <summary>单次 JSON DoH 请求的超时，避免端点卡住时把解析拖到分钟级。</summary>
    private static readonly TimeSpan JsonRequestTimeout = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan JsonCacheMinDuration = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan JsonCacheMaxDuration = TimeSpan.FromMinutes(5);

    private DnsQuery()
    {
        var proxyHandler = new HttpClientHandler()
        {
            Proxy = HttpProxyManager.Instance
        };
        // 使用Ae.Dns创建DoH客户端，支持多个DoH服务器
        _httpClients =
        [
            new HttpClient(proxyHandler)
            {
                BaseAddress = new Uri("https://doh.pub/")
            },
            new HttpClient(proxyHandler)
            {
                BaseAddress = new Uri("https://doh.pysio.online/")
            },
            new HttpClient(proxyHandler)
            {
                BaseAddress = new Uri("https://cloudflare-dns.com/")
            }
        ];
        _jsonClient = new HttpClient(proxyHandler);
        _resolver = new DnsCachingClient(
            new WeightedDnsRacerClient(2, _httpClients.Select(static x => new DnsHttpClient(x)).ToArray<IDnsClient>()),
            new MemoryCache("DoH Query Cache"));
    }

    public async Task<DnsMessage?> QueryAsync(string host, DnsQueryType qType, CancellationToken cts = default)
    {
        const int maxAttempts = 2;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await _resolver.Query(DnsQueryFactory.CreateQuery(host, qType), cts);
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
                // 调用方主动取消，直接向上抛出
                throw;
            }
            catch (Exception ex)
            {
                // DoH 自身的超时同样会抛出取消异常，此时不应中断整个连接流程，而是重试或回退到系统 DNS
                if (attempt < maxAttempts)
                {
                    LogWrapper.Debug(ModuleName, $"DoH 查询失败，准备重试 {host}：{ex.Message}");
                    continue;
                }

                LogWrapper.Warn(ModuleName, $"Failed to resolve DNS for {host}: {ex.Message}, use system default DNS");
            }

            return null;
        }
    }

    public async Task<IPAddress[]?> QueryForIpAsync(string host, CancellationToken cts = default)
    {
        var queryResponse = await Task.WhenAll(
            [
                QueryAsync(host, DnsQueryType.A, cts),
                QueryAsync(host, DnsQueryType.AAAA, cts)
            ]
        );

        var addresses = queryResponse.Where(static x => x is not null)
            .SelectMany(static x => x!.Answers)
            .Where(static x => x.Type is DnsQueryType.A or DnsQueryType.AAAA)
            .Select(static x => x.Resource as DnsIpAddressResource)
            .Where(static x => x is not null)
            .Select(static x => x!.IPAddress)
            .ToArray();

        // 滤除已知的污染地址，避免把时间浪费在必然超时的连接上
        var cleanAddresses = addresses.Where(static x => !IsSuspicious(x)).ToArray();
        if (cleanAddresses.Length > 0)
            return cleanAddresses;

        // DoH 结果全部可疑：改用 JSON 接口重新查询（通常能拿到未被污染的结果）
        if (addresses.Length > 0)
            LogWrapper.Debug(ModuleName,
                $"{host} 的 DoH 结果均为已知污染地址（{string.Join(", ", addresses.Select(static x => x.ToString()))}），改用 JSON DoH 重新查询");

        var jsonAddresses = (await QueryJsonAsync(host, cts).ConfigureAwait(false))
            .Where(static x => !IsSuspicious(x)).ToArray();
        if (jsonAddresses.Length > 0)
        {
            LogWrapper.Debug(ModuleName,
                $"JSON DoH 为 {host} 解析到 {string.Join(", ", jsonAddresses.Select(static x => x.ToString()))}");
            return jsonAddresses;
        }

        // JSON 查询也没拿到可用地址：交给系统 DNS，而不是把已知不可用的污染地址交给连接层去挨个超时
        LogWrapper.Warn(ModuleName, $"DoH 未能为 {host} 解析到可用地址，改用系统默认 DNS");
        return await System.Net.Dns.GetHostAddressesAsync(host, cts);
    }

    private static bool IsSuspicious(IPAddress address)
    {
        var text = address.ToString();
        return SuspiciousPrefixes.Any(prefix => text.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private async Task<IPAddress[]> QueryJsonAsync(string host, CancellationToken cts)
    {
        if (_jsonCache.TryGetValue(host, out var cached) && cached.ExpireAt > DateTime.UtcNow)
            return cached.Addresses;

        var result = new List<IPAddress>();
        var minTtl = int.MaxValue;
        foreach (var recordType in new[] { "A", "AAAA" })
        {
            var found = false;
            foreach (var server in JsonDohServers)
            {
                try
                {
                    var url = $"{server}?name={Uri.EscapeDataString(host)}&type={recordType}";
                    using var request = new HttpRequestMessage(HttpMethod.Get, url);
                    request.Headers.Accept.ParseAdd("application/dns-json");
                    // 单次请求单独设超时：端点卡住时不应把整次解析拖到分钟级
                    using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(cts);
                    requestTimeout.CancelAfter(JsonRequestTimeout);
                    using var response = await _jsonClient.SendAsync(request, requestTimeout.Token).ConfigureAwait(false);
                    if (!response.IsSuccessStatusCode) continue;
                    var json = await response.Content.ReadAsStringAsync(requestTimeout.Token).ConfigureAwait(false);
                    var answers = JsonNode.Parse(json)?["Answer"]?.AsArray();
                    if (answers is null) continue;

                    foreach (var answer in answers)
                    {
                        if (answer is not JsonObject answerObject) continue;
                        var data = answerObject["data"]?.ToString();
                        if (string.IsNullOrWhiteSpace(data) || !IPAddress.TryParse(data, out var address)) continue;
                        // 污染过的答案不予采纳，继续尝试下一台服务器
                        if (IsSuspicious(address)) continue;

                        result.Add(address);
                        found = true;

                        // 已采纳记录中最小的 TTL 决定缓存时长，避免记录变更后仍返回过期地址
                        if (int.TryParse(answerObject["TTL"]?.ToString(), out var ttl) && ttl > 0 && ttl < minTtl)
                            minTtl = ttl;
                    }

                    // 只有真正取到地址才停止尝试后续服务器；空应答时继续问下一台
                    if (found) break;
                }
                catch (OperationCanceledException) when (cts.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    LogWrapper.Debug(ModuleName,
                        $"JSON DoH 查询 {host} 的 {recordType} 记录失败（{server}）：{ex.Message}");
                }
            }
        }

        var addresses = result.Distinct().ToArray();
        if (addresses.Length > 0)
        {
            var duration = minTtl == int.MaxValue
                ? JsonCacheMaxDuration
                : TimeSpan.FromSeconds(Math.Clamp(minTtl, JsonCacheMinDuration.TotalSeconds,
                    JsonCacheMaxDuration.TotalSeconds));
            _jsonCache[host] = (addresses, DateTime.UtcNow + duration);
        }

        return addresses;
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        foreach (var client in _httpClients)
        {
            client.Dispose();
        }

        _jsonClient.Dispose();
        _resolver.Dispose(); // 好像这个包的 Dispose 并没有做什么 lol
    }
}
