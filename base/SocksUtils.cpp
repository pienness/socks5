#include "muduo/cdns/Resolver.h"
#include "SocksUtils.h"
#include <memory>

// 用于DNS解析的上下文结构，支持超时和取消操作
struct ResolveContext {
    SocksAddressParseCallback succeeded_cb;
    SocksAddressParseFailedCallback failed_cb;
    muduo::net::TimerId timeout_timer;
    muduo::net::EventLoop* loop;
    bool called = false;
    std::string hostname; // 存储正在解析的主机名，便于日志
    
    ResolveContext(muduo::net::EventLoop* l, 
                  SocksAddressParseCallback success, 
                  SocksAddressParseFailedCallback fail,
                  const std::string& host)
        : succeeded_cb(std::move(success)), 
          failed_cb(std::move(fail)),
          loop(l),
          hostname(host) {}
          
    ~ResolveContext() {
        // 确保清理定时器资源
        if (timeout_timer) {
            loop->cancel(timeout_timer);
        }
    }
    
    // 安全调用回调函数，确保只调用一次
    void callSuccessCallback(const muduo::net::InetAddress& addr) {
        if (!called) {
            called = true;
            LOG_INFO << "域名 " << hostname << " 解析成功: " << addr.toIpPort();
            succeeded_cb(addr);
        }
    }
    
    void callFailureCallback() {
        if (!called) {
            called = true;
            LOG_WARN << "域名 " << hostname << " 解析失败";
            failed_cb();
        }
    }
};

void parseSocksToInetAddress(muduo::net::EventLoop *loop, const void *atyp, 
                            SocksAddressParseCallback succeeded_cb, 
                            SocksAddressParseFailedCallback failed_cb,
                            double timeout_seconds)
{
    static cdns::Resolver resolver(loop);
    auto p = static_cast<const char *>(atyp);
    char addr_type = *p++;  // now p is atyp + 1
    
    // 确保回调函数有效
    if (!succeeded_cb || !failed_cb) {
        LOG_ERROR << "解析回调函数无效";
        if (failed_cb) failed_cb();
        return;
    }
    
    switch(addr_type) {
        case '\x01':     // ATYP: IPv4
        {
            const void *ip = p;
            const void *port = p + 4;
            sockaddr_in sock_addr {};
            muduo::memZero(&sock_addr, sizeof(sock_addr));
            sock_addr.sin_family = AF_INET;
            sock_addr.sin_addr.s_addr = *static_cast<const uint32_t *>(ip);
            sock_addr.sin_port = *static_cast<const uint16_t *>(port);
            succeeded_cb(muduo::net::InetAddress(sock_addr));
            return;
        }
        case '\x03':    // ATYP: hostname
        {
            const char hostname_len = *p++;
            const void *p_port = p + hostname_len;
            std::string hostname(p, p + hostname_len);
            auto port = htons(*static_cast<const uint16_t *>(p_port));
            
            // 日志记录解析请求
            LOG_INFO << "开始解析域名: " << hostname << ":" << port << " (超时: " << timeout_seconds << "秒)";
            
            // 创建共享上下文，在回调中使用
            auto ctx = std::make_shared<ResolveContext>(
                loop, 
                [succeeded_cb, port](const muduo::net::InetAddress &resolved_addr) {
                    succeeded_cb(muduo::net::InetAddress(resolved_addr.toIp(), port));
                }, 
                failed_cb,
                hostname
            );
            
            // 设置超时定时器
            ctx->timeout_timer = loop->runAfter(timeout_seconds, [ctx]() {
                LOG_WARN << "域名解析超时: " << ctx->hostname;
                ctx->callFailureCallback();
            });
            
            // 执行解析，使用智能指针确保资源正确清理
            if (!resolver.resolve(hostname, [ctx](const muduo::net::InetAddress &resolved_addr) {
                // 取消超时定时器
                if (ctx->timeout_timer) {
                    ctx->loop->cancel(ctx->timeout_timer);
                    ctx->timeout_timer = muduo::net::TimerId();
                }
                
                ctx->callSuccessCallback(resolved_addr);
            })) {
                // 解析立即失败的情况
                LOG_ERROR << "域名 " << hostname << " 解析初始化失败";
                ctx->callFailureCallback();
                
                // 取消超时定时器
                if (ctx->timeout_timer) {
                    loop->cancel(ctx->timeout_timer);
                    ctx->timeout_timer = muduo::net::TimerId();
                }
            }
            return;
        }
        case '\x04':    // ATYP: IPv6
        {
            const void *ip6 = p;
            const void *port = p + 16;
            sockaddr_in6 sock_addr;
            muduo::memZero(&sock_addr, sizeof(sock_addr));
            sock_addr.sin6_family = AF_INET6;
            std::copy(static_cast<const uint8_t *>(ip6), static_cast<const uint8_t *>(ip6) + 16, sock_addr.sin6_addr.s6_addr);
            sock_addr.sin6_port = *static_cast<const uint16_t *>(port);
            succeeded_cb(muduo::net::InetAddress(sock_addr));
            return;
        }
        default:
            LOG_ERROR << "无效的地址类型: " << static_cast<int>(addr_type);
            failed_cb();
            return;
    }
}
