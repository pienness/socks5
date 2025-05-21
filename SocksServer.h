//
// Created by clay on 10/22/22.
//

#ifndef SOCKS5_SOCKSSERVER_H
#define SOCKS5_SOCKSSERVER_H

#include <cstddef>
#include <cstdint>
#include <muduo/net/TcpServer.h>
#include "base/SocksResponse.h"
#include "base/ConnectionQueue.h"
#include "muduo/base/Logging.h"
#include "muduo/net/InetAddress.h"
#include "tunnel.h"

class SocksServer : muduo::noncopyable {
public:
    SocksServer(muduo::net::EventLoop *loop, 
                const muduo::net::InetAddress &listenAddr,
                bool noAuth = false,
                bool useDynamicPassword = true,
                const std::string &username = "",  // is this ref valid?
                const std::string &password = "",  // is this ref valid?
                bool skipLocal = true,
                std::size_t connMaxNum = 163,
                std::size_t highMarkKB = 1024,
                double dnsTimeoutSeconds = 10.0) : 
        server_(loop, listenAddr, "SocksServer"),
        loop_(loop), 
        tunnels_(connMaxNum),
        status_(connMaxNum),
        cq_(connMaxNum, connMaxNum * 2),
        tunnelPeekCount_(0),
        statusPeekCount_(0),
        associationAddr_(),
        noAuth_(noAuth),
        useDynamicPassword_(useDynamicPassword),
        username_(username),
        password_(password),
        skipLocal_(skipLocal),
        highMarkKB_(highMarkKB),
        dnsTimeoutSeconds_(dnsTimeoutSeconds)
    {
        server_.setConnectionCallback([this] (const auto &conn) {
            onConnection(conn);
        });
        server_.setMessageCallback([this] (const auto &conn, auto *buf, auto time) {
            onMessage(conn, buf, time);
        });
    }
    void setAssociationAddr(const muduo::net::InetAddress &addr) 
    {
        associationAddr_ = addr;
        LOG_WARN << server_.name() << " UDP Association address on " << associationAddr_.toIpPort();
    }
    bool isSkipLocal() const { return skipLocal_; }
    void start() 
    { 
        LOG_WARN << server_.name() << " start on " << server_.ipPort();
        server_.start(); 
    }
private:
    void onConnection(const muduo::net::TcpConnectionPtr &conn);
    void onMessage(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp);
    void handleWREQ(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void handleWVLDT(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void handleWCMD(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);
    void handleESTABL(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf, muduo::Timestamp time);

    static inline void shutdownSocksReq(const muduo::net::TcpConnectionPtr &conn, muduo::net::Buffer *buf)
    {
        SocksResponse rep;
        rep.initGeneralResponse('\x07');
        conn->send(rep.responseData(), rep.responseSize());
        buf->retrieveAll();
    }

    enum Status {
        WREQ, WVLDT, WCMD, ESTABL
    };
    muduo::net::TcpServer server_;
    muduo::net::EventLoop *loop_;

    HashMap<int64_t, TunnelPtr> tunnels_;
    HashMap<int64_t, Status> status_;
    ConnectionQueue<int64_t> cq_;
    int tunnelPeekCount_;
    int statusPeekCount_;

    muduo::net::InetAddress associationAddr_;

    const bool noAuth_;
    const bool useDynamicPassword_;
    const std::string username_;
    const std::string password_;

    const bool skipLocal_;

    const std::size_t highMarkKB_;
    const double dnsTimeoutSeconds_; // DNS解析超时时间（秒）
};


#endif //SOCKS5_SOCKSSERVER_H
