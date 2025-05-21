#ifndef UDP_ASSOCIATE_H
#define UDP_ASSOCIATE_H

#include "muduo/base/Logging.h"
#include "muduo/cdns/Resolver.h"
#include "muduo/net/Channel.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/InetAddress.h"
#include "base/SocksUtils.h"
#include <chrono>
#include <map>
#include <memory>
#include <string>

// thread not safe
class UdpTunnel {
    constexpr static size_t UDP_TUNNEL_BUF_SZ { 65536 };
public:
    using MessageFilter = std::function<std::string(const std::string&)>;
    using TimePoint = std::chrono::steady_clock::time_point;

    UdpTunnel(const UdpTunnel &) = delete;
    ~UdpTunnel()
    {
        ch_->disableReading();
        ::close(ch_->fd());
    }

    UdpTunnel(muduo::net::EventLoop *loop,
              const muduo::net::InetAddress &src,
              int src_fd) :
        buf_(), 
        src_fd_(src_fd), 
        src_(src), 
        ch_(), 
        message_filter_([](const auto &msg) { return msg; }),
        last_activity_(std::chrono::steady_clock::now())
    {
        auto fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            LOG_FATAL << "Socket < 0";
        }
        ch_.reset(new muduo::net::Channel(loop, fd));
        assert(ch_);
        ch_->setReadCallback([this](muduo::Timestamp timestamp) { messageCallback(timestamp); });
        ch_->enableReading();
    }
    
    // 发送数据并更新活跃时间
    ssize_t send(const void *buf, size_t n, const muduo::net::InetAddress &dst) 
    {
        last_activity_ = std::chrono::steady_clock::now();
        return sendto(ch_->fd(), buf, n, 0, dst.getSockAddr(), sizeof(sockaddr));
    }
    
    void setMessageFilter(MessageFilter filter_) { std::swap(filter_, message_filter_); }
    void resetMessageFilter() { message_filter_ = [](const auto &msg) { return msg; }; }
    
    // 获取最后活跃时间
    TimePoint lastActivity() const { return last_activity_; }
    
private:
    ssize_t sendBackToSrc(const void *buf, size_t n) 
    {
        last_activity_ = std::chrono::steady_clock::now();
        return sendto(src_fd_, buf, n, 0, src_.getSockAddr(), sizeof(sockaddr));
    }
    
    void messageCallback(muduo::Timestamp timestamp)
    {
        sockaddr_in addr {};
        muduo::memZero(&addr, sizeof(addr));
        socklen_t len { sizeof(addr) };
        auto rcv_len = recvfrom(ch_->fd(), buf_, sizeof(buf_), 0, reinterpret_cast<sockaddr*>(&addr), &len);
        if (rcv_len < 0) {
            LOG_FATAL << "rcv_len < 0";
        }
        muduo::net::InetAddress dst_addr(addr);
        LOG_INFO << rcv_len << " bytes received from " << dst_addr.toIpPort();
        std::string res = message_filter_(std::string(buf_, buf_ + rcv_len));
        auto snt_len = sendBackToSrc(res.c_str(), res.size());
        LOG_INFO << snt_len << " bytes from " << dst_addr.toIpPort() << " sent back to " << src_.toIpPort();
    }

    char buf_[UDP_TUNNEL_BUF_SZ];
    int src_fd_;
    muduo::net::InetAddress src_;
    std::unique_ptr<muduo::net::Channel> ch_;
    MessageFilter message_filter_;
    TimePoint last_activity_;  // 最后活跃时间
};

// UdpAssociation管理UDP转发
class UdpAssociation : public std::enable_shared_from_this<UdpAssociation>, muduo::noncopyable {
    constexpr static size_t UDP_ASSOCIATION_BUF_SZ { 65536 };
    constexpr static int DEFAULT_TIMEOUT_SECONDS { 300 };  // 默认5分钟超时
    
public:
    using Tunnel = std::unique_ptr<UdpTunnel>;
    using TimePoint = typename UdpTunnel::TimePoint;

    UdpAssociation(const UdpAssociation &) = delete;
    ~UdpAssociation() 
    { 
        if (cleanup_timer_) {
            loop_->cancel(cleanup_timer_);
        }
        ch_->disableReading();
        ::close(ch_->fd()); 
    }
    
    explicit UdpAssociation(muduo::net::EventLoop *loop, 
                           const muduo::net::InetAddress &association_addr,
                           int timeout_seconds = DEFAULT_TIMEOUT_SECONDS): 
        loop_(loop), 
        skip_local_address_(true),
        timeout_seconds_(timeout_seconds)
    {
        auto fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            LOG_FATAL << "Socket < 0";
        }
        auto ret = ::bind(fd, association_addr.getSockAddr(), sizeof(sockaddr));
        if (ret < 0) {
            LOG_FATAL << "Bind < 0";
        }
        ch_.reset(new muduo::net::Channel(loop, fd));
        ch_->setReadCallback([this](muduo::Timestamp timestamp) {
            readCallback(timestamp);
        });
        ch_->enableReading();
        
        // 设置定期清理定时器
        setupCleanupTimer();
        
        LOG_WARN << "UDP Association started on " << association_addr.toIpPort() 
                << " (timeout: " << timeout_seconds_ << "s)";
    }
    
    bool isSkipLocal() const { return skip_local_address_; }
    void skipLocal(bool skip=true) { skip_local_address_ = skip; }
    
    // 设置UDP隧道超时时间（秒）
    void setTimeout(int seconds) {
        timeout_seconds_ = seconds;
        LOG_INFO << "UDP tunnel timeout set to " << seconds << " seconds";
    }
    
private:
    // 设置定期清理定时器
    void setupCleanupTimer() {
        // 每60秒检查一次过期的通道
        cleanup_timer_ = loop_->runEvery(60.0, [this]() {
            cleanupExpiredTunnels();
        });
    }
    
    // 清理过期的UDP隧道
    void cleanupExpiredTunnels() {
        auto now = std::chrono::steady_clock::now();
        std::vector<std::string> expired_keys;
        
        // 找出所有过期的通道
        for (const auto& pair : association_) {
            auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
                now - pair.second->lastActivity()).count();
                
            if (idle_time > timeout_seconds_) {
                expired_keys.push_back(pair.first);
                LOG_INFO << "UDP tunnel to " << pair.first << " expired after " 
                        << idle_time << "s of inactivity";
            }
        }
        
        // 删除过期通道
        for (const auto& key : expired_keys) {
            association_.erase(key);
        }
        
        if (!expired_keys.empty()) {
            LOG_INFO << "Cleaned up " << expired_keys.size() 
                    << " expired UDP tunnels, " << association_.size() << " remaining";
        }
    }
    
    void readCallback(muduo::Timestamp timestamp)
    {
        LOG_DEBUG << "Association fd " << ch_->fd() << " readable on " << timestamp.toFormattedString();
        sockaddr_in addr {};
        muduo::memZero(&addr, sizeof(sockaddr_in));
        socklen_t len { sizeof(addr) };
        auto rcv_len = recvfrom(ch_->fd(), buf_, sizeof(buf_), 0, reinterpret_cast<sockaddr*>(&addr), &len);
        muduo::net::InetAddress from_addr(addr);
        if (rcv_len < 0) { 
            LOG_FATAL << "Error in recvfrom";
        }
        if (rcv_len <= 4) return;
        // TODO: frag
        if (std::string(buf_, buf_ + 3) != std::string { '\x00', '\x00', '\x00' }) return;
        auto p = buf_ + 3;
        char *data {};
        std::string domain {};
        switch (testSocksAddressType(p, rcv_len)) {
            case SocksAddressType::IPv4:
                data = p + 1 + 4 + 2;
                break;
            case SocksAddressType::IPv6:
                data = p + 1 + 16 + 2;
                break;
            case SocksAddressType::DOMAIN_NAME:
                domain = parseSocksDomainName(p + 1);
                data = p + 1 + p[1] + 2;
                break;
            case SocksAddressType::INCOMPLETED:
            case SocksAddressType::INVALID:
                LOG_ERROR << "Invalid UDP request format from " << from_addr.toIpPort();
                return;
        }
        auto head_len = std::distance(buf_, data);
        auto data_len = rcv_len - head_len;
        std::string head(buf_, buf_ + head_len);
        
        // 使用弱指针避免循环引用
        auto weak_this = this;
        
        parseSocksToInetAddress(loop_, p, 
        [this, weak_this, data, data_len, head, from_addr](const auto &dst_addr) {
            // 检查local跳过规则
            if (skip_local_address_ && isLocalIP(dst_addr)) {
                LOG_ERROR << "ASSOCIATE to local address " << dst_addr.toIpPort() << " blocked";
                return;
            }
            
            auto key = from_addr.toIpPort();
            if (!association_.count(key)) {
                LOG_INFO << "Creating new UDP tunnel for " << key << " to " << dst_addr.toIpPort();
                auto p = association_.insert({ key, std::unique_ptr<UdpTunnel>() });
                p.first->second.reset(new UdpTunnel(loop_, from_addr, ch_->fd()));
                p.first->second->setMessageFilter([head](const auto &msg) {
                    return head + msg;
                });
            }
            
            auto sent_len = association_[key]->send(data, data_len, dst_addr);
            if (sent_len < 0) {
                LOG_ERROR << "Error sending UDP data to " << dst_addr.toIpPort();
            } else {
                LOG_INFO << sent_len << " bytes from " << from_addr.toIpPort() 
                        << " associate to " << dst_addr.toIpPort();
            }
        }, 
        [domain, from_addr]{
            LOG_ERROR << "Failed to resolve domain " << domain << " for UDP request from " << from_addr.toIpPort();
        },
        10.0); // UDP域名解析使用10秒超时
    }

    char buf_[UDP_ASSOCIATION_BUF_SZ];
    std::unique_ptr<muduo::net::Channel> ch_;
    std::map<std::string, Tunnel> association_;
    muduo::net::EventLoop *loop_;
    bool skip_local_address_;
    int timeout_seconds_;  // UDP隧道的超时时间（秒）
    muduo::net::TimerId cleanup_timer_;  // 定期清理定时器
};

#endif  // UDP_ASSOCIATE_H