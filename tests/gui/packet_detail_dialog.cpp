// tests/gui/packet_detail_dialog.cpp
#include "main_window.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QSplitter>
#include <QHeaderView>
#include <QFont>
#include <QDateTime>
#include <QApplication>
#include <QClipboard>
#include <arpa/inet.h>

PacketDetailDialog::PacketDetailDialog(const ParsedPacket& packet, QWidget *parent)
    : QDialog(parent), m_packet(packet)
{
    setupUI();
    displayPacketDetails(packet);
}

void PacketDetailDialog::setupUI()
{
    setWindowTitle("Packet Details");
    resize(1000, 800);
    
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    // Splitter for tree and hex dump
    QSplitter *splitter = new QSplitter(Qt::Vertical);
    
    // Tree widget for protocol layers
    m_detailTree = new QTreeWidget();
    m_detailTree->setHeaderLabels({"Field", "Value"});
    m_detailTree->setColumnWidth(0, 400);
    m_detailTree->setAlternatingRowColors(true);
    m_detailTree->setExpandsOnDoubleClick(true);
    splitter->addWidget(m_detailTree);
    
    // Hex dump
    m_hexDump = new QTextEdit();
    m_hexDump->setReadOnly(true);
    m_hexDump->setFont(QFont("Courier", 9));
    m_hexDump->setLineWrapMode(QTextEdit::NoWrap);
    splitter->addWidget(m_hexDump);
    
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);
    
    mainLayout->addWidget(splitter);
    
    // Buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    
    QPushButton *copyButton = new QPushButton("Copy Details");
    connect(copyButton, &QPushButton::clicked, [this]() {
        QString text;
        for (int i = 0; i < m_detailTree->topLevelItemCount(); i++) {
            QTreeWidgetItem *item = m_detailTree->topLevelItem(i);
            text += item->text(0) + ": " + item->text(1) + "\n";
            for (int j = 0; j < item->childCount(); j++) {
                QTreeWidgetItem *child = item->child(j);
                text += "  " + child->text(0) + ": " + child->text(1) + "\n";
            }
        }
        QApplication::clipboard()->setText(text);
    });
    
    buttonLayout->addWidget(copyButton);
    buttonLayout->addStretch();
    
    QPushButton *closeButton = new QPushButton("Close");
    closeButton->setDefault(true);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    buttonLayout->addWidget(closeButton);
    
    mainLayout->addLayout(buttonLayout);
}

void PacketDetailDialog::displayPacketDetails(const ParsedPacket& packet)
{
    m_detailTree->clear();
    
    // Frame
    QTreeWidgetItem *frameItem = new QTreeWidgetItem(m_detailTree);
    frameItem->setText(0, QString("Frame %1: %2 bytes")
                       .arg(1)
                       .arg(packet.captured_length));
    frameItem->setExpanded(true);
    
    QTreeWidgetItem *frameLen = new QTreeWidgetItem(frameItem);
    frameLen->setText(0, "Frame Length");
    frameLen->setText(1, QString("%1 bytes").arg(packet.captured_length));
    
    QTreeWidgetItem *frameTime = new QTreeWidgetItem(frameItem);
    frameTime->setText(0, "Arrival Time");
    frameTime->setText(1, QDateTime::fromMSecsSinceEpoch(packet.timestamp / 1000)
                           .toString("yyyy-MM-dd hh:mm:ss.zzz"));
    
    QTreeWidgetItem *frameEpoch = new QTreeWidgetItem(frameItem);
    frameEpoch->setText(0, "Epoch Time");
    frameEpoch->setText(1, QString("%1.%2 seconds")
                        .arg(packet.timestamp / 1000000)
                        .arg(packet.timestamp % 1000000, 6, 10, QChar('0')));
    
    // Add protocol layers
    if (packet.has_ethernet) {
        addEthernetLayer(packet);
    }
    
    if (packet.has_ipv4) {
        addIPv4Layer(packet);
    }
    
    if (packet.has_ipv6) {
        addIPv6Layer(packet);
    }
    
    if (packet.has_arp) {
        addARPLayer(packet);
    }
    
    if (packet.has_tcp) {
        addTCPLayer(packet);
    }
    
    if (packet.has_udp) {
        addUDPLayer(packet);
    }
    
    if (packet.has_icmp) {
        addICMPLayer(packet);
    }
    
    // Payload
    if (packet.payload_length > 0) {
        QTreeWidgetItem *payloadItem = new QTreeWidgetItem(m_detailTree);
        payloadItem->setText(0, QString("Data (%1 bytes)").arg(packet.payload_length));
        payloadItem->setExpanded(false);
        
        QTreeWidgetItem *payloadLen = new QTreeWidgetItem(payloadItem);
        payloadLen->setText(0, "Length");
        payloadLen->setText(1, QString("%1 bytes").arg(packet.payload_length));
    }
    
    // Hex dump
    displayHexDump(packet);
}

void PacketDetailDialog::addEthernetLayer(const ParsedPacket& packet)
{
    QTreeWidgetItem *ethItem = new QTreeWidgetItem(m_detailTree);
    ethItem->setText(0, "Ethernet II");
    ethItem->setExpanded(true);
    
    // Destination MAC
    QTreeWidgetItem *ethDst = new QTreeWidgetItem(ethItem);
    ethDst->setText(0, "Destination");
    ethDst->setText(1, QString::fromStdString(PacketParser::macToString(packet.ethernet.dst_mac)));
    
    // Source MAC
    QTreeWidgetItem *ethSrc = new QTreeWidgetItem(ethItem);
    ethSrc->setText(0, "Source");
    ethSrc->setText(1, QString::fromStdString(PacketParser::macToString(packet.ethernet.src_mac)));
    
    // Type
    QTreeWidgetItem *ethType = new QTreeWidgetItem(ethItem);
    ethType->setText(0, "Type");
    uint16_t ether_type = ntohs(packet.ethernet.ether_type);
    QString type_str;
    switch (ether_type) {
        case 0x0800: type_str = "IPv4 (0x0800)"; break;
        case 0x0806: type_str = "ARP (0x0806)"; break;
        case 0x86DD: type_str = "IPv6 (0x86DD)"; break;
        default: type_str = QString("0x%1").arg(ether_type, 4, 16, QChar('0'));
    }
    ethType->setText(1, type_str);
}

void PacketDetailDialog::addIPv4Layer(const ParsedPacket& packet)
{
    QTreeWidgetItem *ipItem = new QTreeWidgetItem(m_detailTree);
    ipItem->setText(0, "Internet Protocol Version 4");
    ipItem->setExpanded(true);
    
    // Version
    QTreeWidgetItem *ipVer = new QTreeWidgetItem(ipItem);
    ipVer->setText(0, "Version");
    ipVer->setText(1, QString::number(packet.ipv4.version));
    
    // Header Length
    QTreeWidgetItem *ipHdrLen = new QTreeWidgetItem(ipItem);
    ipHdrLen->setText(0, "Header Length");
    ipHdrLen->setText(1, QString("%1 bytes").arg(packet.ipv4.ihl * 4));
    
    // Total Length
    QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(ipItem);
    ipTotalLen->setText(0, "Total Length");
    ipTotalLen->setText(1, QString::number(ntohs(packet.ipv4.total_length)));
    
    // // Identification
    // QTreeWidgetItem *ipId = new QTreeWidgetItem(ipItem);
    // ipId->setText(0, "Identification");
    // ipId->setText(1, QString("0x%1 (%2)")
    //               .arg(ntohs(packet.ipv4.id), 4, 16, QChar('0'))
    //               .arg(ntohs(packet.ipv4.id)));
    
    // Flags
    QTreeWidgetItem *ipFlags = new QTreeWidgetItem(ipItem);
    ipFlags->setText(0, "Flags");
    uint16_t flags = ntohs(packet.ipv4.fragment_offset) >> 13;
    QStringList flagList;
    if (flags & 0x02) flagList << "Don't fragment";
    if (flags & 0x01) flagList << "More fragments";
    ipFlags->setText(1, QString("0x%1 (%2)")
                     .arg(flags, 1, 16)
                     .arg(flagList.isEmpty() ? "None" : flagList.join(", ")));
    
    // Fragment Offset
    QTreeWidgetItem *ipFragOff = new QTreeWidgetItem(ipItem);
    ipFragOff->setText(0, "Fragment Offset");
    ipFragOff->setText(1, QString::number(ntohs(packet.ipv4.fragment_offset) & 0x1FFF));
    
    // TTL
    QTreeWidgetItem *ipTTL = new QTreeWidgetItem(ipItem);
    ipTTL->setText(0, "Time to Live");
    ipTTL->setText(1, QString::number(packet.ipv4.ttl));
    
    // Protocol
    QTreeWidgetItem *ipProto = new QTreeWidgetItem(ipItem);
    ipProto->setText(0, "Protocol");
    QString proto_str;
    switch (packet.ipv4.protocol) {
        case 1: proto_str = "ICMP (1)"; break;
        case 6: proto_str = "TCP (6)"; break;
        case 17: proto_str = "UDP (17)"; break;
        default: proto_str = QString::number(packet.ipv4.protocol);
    }
    ipProto->setText(1, proto_str);
    
    // Header Checksum
    QTreeWidgetItem *ipChecksum = new QTreeWidgetItem(ipItem);
    ipChecksum->setText(0, "Header Checksum");
    ipChecksum->setText(1, QString("0x%1").arg(ntohs(packet.ipv4.checksum), 4, 16, QChar('0')));
    
    // Source IP
    QTreeWidgetItem *ipSrc = new QTreeWidgetItem(ipItem);
    ipSrc->setText(0, "Source Address");
    ipSrc->setText(1, QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.src_ip)));
    
    // Destination IP
    QTreeWidgetItem *ipDst = new QTreeWidgetItem(ipItem);
    ipDst->setText(0, "Destination Address");
    ipDst->setText(1, QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.dst_ip)));
}

void PacketDetailDialog::addIPv6Layer(const ParsedPacket& packet)
{
    QTreeWidgetItem *ipItem = new QTreeWidgetItem(m_detailTree);
    ipItem->setText(0, "Internet Protocol Version 6");
    ipItem->setExpanded(true);
    
    // Version
    QTreeWidgetItem *ipVer = new QTreeWidgetItem(ipItem);
    ipVer->setText(0, "Version");
    ipVer->setText(1, "6");
    
    // Traffic Class
    QTreeWidgetItem *ipTraffic = new QTreeWidgetItem(ipItem);
    ipTraffic->setText(0, "Traffic Class");
    ipTraffic->setText(1, QString("0x%1").arg(packet.ipv6.traffic_class, 2, 16, QChar('0')));
    
    // Flow Label
    QTreeWidgetItem *ipFlow = new QTreeWidgetItem(ipItem);
    ipFlow->setText(0, "Flow Label");
    ipFlow->setText(1, QString("0x%1").arg(ntohl(packet.ipv6.flow_label), 5, 16, QChar('0')));
    
    // Payload Length
    QTreeWidgetItem *ipPayloadLen = new QTreeWidgetItem(ipItem);
    ipPayloadLen->setText(0, "Payload Length");
    ipPayloadLen->setText(1, QString::number(ntohs(packet.ipv6.payload_length)));
    
    // Next Header
    QTreeWidgetItem *ipNextHdr = new QTreeWidgetItem(ipItem);
    ipNextHdr->setText(0, "Next Header");
    ipNextHdr->setText(1, QString::number(packet.ipv6.next_header));
    
    // Hop Limit
    QTreeWidgetItem *ipHopLimit = new QTreeWidgetItem(ipItem);
    ipHopLimit->setText(0, "Hop Limit");
    ipHopLimit->setText(1, QString::number(packet.ipv6.hop_limit));
    
    // Source Address
    QTreeWidgetItem *ipSrc = new QTreeWidgetItem(ipItem);
    ipSrc->setText(0, "Source Address");
    ipSrc->setText(1, QString::fromStdString(PacketParser::ipv6ToString(packet.ipv6.src_ip)));
    
    // Destination Address
    QTreeWidgetItem *ipDst = new QTreeWidgetItem(ipItem);
    ipDst->setText(0, "Destination Address");
    ipDst->setText(1, QString::fromStdString(PacketParser::ipv6ToString(packet.ipv6.dst_ip)));
}

void PacketDetailDialog::addTCPLayer(const ParsedPacket& packet)
{
    QTreeWidgetItem *tcpItem = new QTreeWidgetItem(m_detailTree);
    tcpItem->setText(0, "Transmission Control Protocol");
    tcpItem->setExpanded(true);
    
    // Source Port
    QTreeWidgetItem *tcpSrc = new QTreeWidgetItem(tcpItem);
    tcpSrc->setText(0, "Source Port");
    tcpSrc->setText(1, QString::number(ntohs(packet.tcp.src_port)));
    
    // Destination Port
    QTreeWidgetItem *tcpDst = new QTreeWidgetItem(tcpItem);
    tcpDst->setText(0, "Destination Port");
    tcpDst->setText(1, QString::number(ntohs(packet.tcp.dst_port)));
    
    // Stream
    QTreeWidgetItem *tcpStream = new QTreeWidgetItem(tcpItem);
    tcpStream->setText(0, "Stream");
    tcpStream->setText(1, QString("%1:%2 → %3:%4")
                       .arg(QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.src_ip)))
                       .arg(ntohs(packet.tcp.src_port))
                       .arg(QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.dst_ip)))
                       .arg(ntohs(packet.tcp.dst_port)));
    
    // Sequence Number
    QTreeWidgetItem *tcpSeq = new QTreeWidgetItem(tcpItem);
    tcpSeq->setText(0, "Sequence Number");
    uint32_t seq = ntohl(packet.tcp.seq_number);
    tcpSeq->setText(1, QString("%1 (relative)").arg(seq));
    
    // Acknowledgment Number
    QTreeWidgetItem *tcpAck = new QTreeWidgetItem(tcpItem);
    tcpAck->setText(0, "Acknowledgment Number");
    uint32_t ack = ntohl(packet.tcp.ack_number);
    tcpAck->setText(1, QString("%1 (relative)").arg(ack));
    
    // Header Length
    QTreeWidgetItem *tcpHdrLen = new QTreeWidgetItem(tcpItem);
    tcpHdrLen->setText(0, "Header Length");
    tcpHdrLen->setText(1, QString("%1 bytes").arg(packet.tcp.data_offset * 4));
    
    // Flags
    QTreeWidgetItem *tcpFlags = new QTreeWidgetItem(tcpItem);
    tcpFlags->setText(0, "Flags");
    tcpFlags->setText(1, QString("0x%1").arg(packet.tcp.flags, 3, 16, QChar('0')));
    tcpFlags->setExpanded(true);
    
    struct FlagInfo {
        uint8_t mask;
        QString name;
        QString desc;
    };
    
    FlagInfo flags[] = {
        {0x01, "FIN", "Finish"},
        {0x02, "SYN", "Synchronize"},
        {0x04, "RST", "Reset"},
        {0x08, "PSH", "Push"},
        {0x10, "ACK", "Acknowledgment"},
        {0x20, "URG", "Urgent"},
        {0x40, "ECE", "ECN-Echo"},
        {0x80, "CWR", "Congestion Window Reduced"}
    };
    
    for (const auto& flag : flags) {
        QTreeWidgetItem *flagItem = new QTreeWidgetItem(tcpFlags);
        flagItem->setText(0, QString("%1 (%2)").arg(flag.name, flag.desc));
        flagItem->setText(1, (packet.tcp.flags & flag.mask) ? "Set" : "Not set");
    }
    
    // Window Size
    QTreeWidgetItem *tcpWin = new QTreeWidgetItem(tcpItem);
    tcpWin->setText(0, "Window Size");
    tcpWin->setText(1, QString::number(ntohs(packet.tcp.window_size)));
    
    // Checksum
    QTreeWidgetItem *tcpChecksum = new QTreeWidgetItem(tcpItem);
    tcpChecksum->setText(0, "Checksum");
    tcpChecksum->setText(1, QString("0x%1").arg(ntohs(packet.tcp.checksum), 4, 16, QChar('0')));
    
    // Urgent Pointer
    QTreeWidgetItem *tcpUrg = new QTreeWidgetItem(tcpItem);
    tcpUrg->setText(0, "Urgent Pointer");
    tcpUrg->setText(1, QString::number(ntohs(packet.tcp.urgent_pointer)));
}

void PacketDetailDialog::addUDPLayer(const ParsedPacket& packet)
{
    QTreeWidgetItem *udpItem = new QTreeWidgetItem(m_detailTree);
    udpItem->setText(0, "User Datagram Protocol");
    udpItem->setExpanded(true);
    
    // Source Port
    QTreeWidgetItem *udpSrc = new QTreeWidgetItem(udpItem);
    udpSrc->setText(0, "Source Port");
    udpSrc->setText(1, QString::number(ntohs(packet.udp.src_port)));
    
    // Destination Port
    QTreeWidgetItem *udpDst = new QTreeWidgetItem(udpItem);
    udpDst->setText(0, "Destination Port");
    udpDst->setText(1, QString::number(ntohs(packet.udp.dst_port)));
    
    // Length
    QTreeWidgetItem *udpLen = new QTreeWidgetItem(udpItem);
    udpLen->setText(0, "Length");
    udpLen->setText(1, QString::number(ntohs(packet.udp.length)));
    
    // Checksum
    QTreeWidgetItem *udpChecksum = new QTreeWidgetItem(udpItem);
    udpChecksum->setText(0, "Checksum");
    udpChecksum->setText(1, QString("0x%1").arg(ntohs(packet.udp.checksum), 4, 16, QChar('0')));
    
    // Stream
    QTreeWidgetItem *udpStream = new QTreeWidgetItem(udpItem);
    udpStream->setText(0, "Stream");
    udpStream->setText(1, QString("%1:%2 → %3:%4")
                       .arg(QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.src_ip)))
                       .arg(ntohs(packet.udp.src_port))
                       .arg(QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.dst_ip)))
                       .arg(ntohs(packet.udp.dst_port)));
}

void PacketDetailDialog::addICMPLayer(const ParsedPacket& packet)
{
    QTreeWidgetItem *icmpItem = new QTreeWidgetItem(m_detailTree);
    icmpItem->setText(0, "Internet Control Message Protocol");
    icmpItem->setExpanded(true);
    
    // Type
    QTreeWidgetItem *icmpType = new QTreeWidgetItem(icmpItem);
    icmpType->setText(0, "Type");
    QString type_str;
    switch (packet.icmp.type) {
        case 0: type_str = "Echo Reply (0)"; break;
        case 3: type_str = "Destination Unreachable (3)"; break;
        case 8: type_str = "Echo Request (8)"; break;
        case 11: type_str = "Time Exceeded (11)"; break;
        default: type_str = QString::number(packet.icmp.type);
    }
    icmpType->setText(1, type_str);
    
    // Code
    QTreeWidgetItem *icmpCode = new QTreeWidgetItem(icmpItem);
    icmpCode->setText(0, "Code");
    icmpCode->setText(1, QString::number(packet.icmp.code));
    
    // Checksum
    QTreeWidgetItem *icmpChecksum = new QTreeWidgetItem(icmpItem);
    icmpChecksum->setText(0, "Checksum");
    icmpChecksum->setText(1, QString("0x%1").arg(ntohs(packet.icmp.checksum), 4, 16, QChar('0')));
    
    // // Identifier
    // QTreeWidgetItem *icmpId = new QTreeWidgetItem(icmpItem);
    // icmpId->setText(0, "Identifier");
    // icmpId->setText(1, QString("0x%1").arg(ntohs(packet.icmp.id), 4, 16, QChar('0')));
    
    // Sequence Number
    QTreeWidgetItem *icmpSeq = new QTreeWidgetItem(icmpItem);
    icmpSeq->setText(0, "Sequence Number");
    icmpSeq->setText(1, QString::number(ntohs(packet.icmp.sequence)));
}

void PacketDetailDialog::addARPLayer(const ParsedPacket& packet)
{
    QTreeWidgetItem *arpItem = new QTreeWidgetItem(m_detailTree);
    arpItem->setText(0, "Address Resolution Protocol");
    arpItem->setExpanded(true);
    
    // Hardware Type
    QTreeWidgetItem *arpHwType = new QTreeWidgetItem(arpItem);
    arpHwType->setText(0, "Hardware Type");
    arpHwType->setText(1, QString("Ethernet (0x%1)")
                       .arg(ntohs(packet.arp.hardware_type), 4, 16, QChar('0')));
    
    // Protocol Type
    QTreeWidgetItem *arpProtoType = new QTreeWidgetItem(arpItem);
    arpProtoType->setText(0, "Protocol Type");
    arpProtoType->setText(1, QString("IPv4 (0x%1)")
                          .arg(ntohs(packet.arp.protocol_type), 4, 16, QChar('0')));
    
    // Hardware Size
    QTreeWidgetItem *arpHwSize = new QTreeWidgetItem(arpItem);
    arpHwSize->setText(0, "Hardware Size");
    arpHwSize->setText(1, QString::number(packet.arp.hardware_type));
    
    // Protocol Size
    QTreeWidgetItem *arpProtoSize = new QTreeWidgetItem(arpItem);
    arpProtoSize->setText(0, "Protocol Size");
    arpProtoSize->setText(1, QString::number(packet.arp.protocol_size));
    
    // Opcode
    QTreeWidgetItem *arpOpcode = new QTreeWidgetItem(arpItem);
    arpOpcode->setText(0, "Opcode");
    uint16_t opcode = ntohs(packet.arp.opcode);
    QString opcode_str = (opcode == 1) ? "Request (1)" : "Reply (2)";
    arpOpcode->setText(1, opcode_str);
    
    // Sender MAC
    QTreeWidgetItem *arpSenderMac = new QTreeWidgetItem(arpItem);
    arpSenderMac->setText(0, "Sender MAC Address");
    arpSenderMac->setText(1, QString::fromStdString(PacketParser::macToString(packet.arp.sender_mac)));
    
    // Sender IP
    QTreeWidgetItem *arpSenderIp = new QTreeWidgetItem(arpItem);
    arpSenderIp->setText(0, "Sender IP Address");
    arpSenderIp->setText(1, QString::fromStdString(PacketParser::ipv4ToString(packet.arp.sender_ip)));
    
    // Target MAC
    QTreeWidgetItem *arpTargetMac = new QTreeWidgetItem(arpItem);
    arpTargetMac->setText(0, "Target MAC Address");
    arpTargetMac->setText(1, QString::fromStdString(PacketParser::macToString(packet.arp.target_mac)));
    
    // Target IP
    QTreeWidgetItem *arpTargetIp = new QTreeWidgetItem(arpItem);
    arpTargetIp->setText(0, "Target IP Address");
    arpTargetIp->setText(1, QString::fromStdString(PacketParser::ipv4ToString(packet.arp.target_ip)));
}

void PacketDetailDialog::displayHexDump(const ParsedPacket& packet)
{
    QString hexDump;
    
    if (packet.payload_length > 0) {
        size_t display_len = std::min(static_cast<size_t>(packet.payload_length), 
                                     static_cast<size_t>(2048));
        
        hexDump += QString("Data (%1 bytes):\n\n").arg(packet.payload_length);
        
        for (size_t i = 0; i < display_len; i += 16) {
            // Offset
            hexDump += QString("%1  ").arg(i, 4, 16, QChar('0')).toUpper();
            
            // Hex bytes
            QString hex_part;
            QString ascii_part;
            
            for (size_t j = 0; j < 16; j++) {
                if (i + j < display_len) {
                    unsigned char byte = static_cast<unsigned char>(packet.payload[i + j]);
                    hex_part += QString("%1 ").arg(byte, 2, 16, QChar('0')).toUpper();
                    ascii_part += (byte >= 32 && byte <= 126) ? QChar(byte) : QChar('.');
                } else {
                    hex_part += "   ";
                    ascii_part += " ";
                }
                
                // Add extra space in the middle
                if (j == 7) {
                    hex_part += " ";
                }
            }
            
            hexDump += hex_part + "  " + ascii_part + "\n";
        }
        
        if (packet.payload_length > 2048) {
            hexDump += QString("\n... (%1 more bytes not shown)").arg(packet.payload_length - 2048);
        }
    } else {
        hexDump = "No payload data";
    }
    
    m_hexDump->setPlainText(hexDump);
}
