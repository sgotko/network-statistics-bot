import { NodeSSH } from "node-ssh";
import { Resolver } from "dns/promises";
import dotevn from "dotenv";
dotevn.config();
import fetch from "node-fetch";
import { FormData } from "formdata-node";
import TextToImage from "text-to-image";
import fs from "fs/promises";
const MAX_HOSTNAME_LENGTH = process.env.MAX_HOSTNAME_LENGTH || 30;
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const resolveHostname = async (ip) => {
  const resolver = new Resolver();
  if (process.env.DNS_SERVER) resolver.setServers([process.env.DNS_SERVER]);
  try {
    const hostnames = await resolver.reverse(ip);
    //   .replace(".lugacom.local", "");
    return hostnames[0];
  } catch (e) {
    return ip;
  }
};

const protocols = {
  0: "HOPOPT",
  1: "ICMP",
  2: "IGMP",
  3: "GGP",
  4: "IPv4",
  5: "ST",
  6: "TCP",
  7: "CBT",
  8: "EGP",
  9: "IGP",
  10: "BBN-RCC-MON",
  11: "NVP-II",
  12: "PUP",
  13: "ARGUS (deprecated)",
  14: "EMCON",
  15: "XNET",
  16: "CHAOS",
  17: "UDP",
  18: "MUX",
  19: "DCN-MEAS",
  20: "HMP",
  21: "PRM",
  22: "XNS-IDP",
  23: "TRUNK-1",
  24: "TRUNK-2",
  25: "LEAF-1",
  26: "LEAF-2",
  27: "RDP",
  28: "IRTP",
  29: "ISO-TP4",
  30: "NETBLT",
  31: "MFE-NSP",
  32: "MERIT-INP",
  33: "DCCP",
  34: "3PC",
  35: "IDPR",
  36: "XTP",
  37: "DDP",
  38: "IDPR-CMTP",
  39: "TP++",
  40: "IL",
  41: "IPv6",
  42: "SDRP",
  43: "IPv6-Route",
  44: "IPv6-Frag",
  45: "IDRP",
  46: "RSVP",
  47: "GRE",
  48: "DSR",
  49: "BNA",
  50: "ESP",
  51: "AH",
  52: "I-NLSP",
  53: "SWIPE (deprecated)",
  54: "NARP",
  55: "MOBILE",
  56: "TLSP",
  57: "SKIP",
  58: "IPv6-ICMP",
  59: "IPv6-NoNxt",
  60: "IPv6-Opts",
  62: "CFTP",
  64: "SAT-EXPAK",
  65: "KRYPTOLAN",
  66: "RVD",
  67: "IPPC",
  69: "SAT-MON",
  70: "VISA",
  71: "IPCV",
  72: "CPNX",
  73: "CPHB",
  74: "WSN",
  75: "PVP",
  76: "BR-SAT-MON",
  77: "SUN-ND",
  78: "WB-MON",
  79: "WB-EXPAK",
  80: "ISO-IP",
  81: "VMTP",
  82: "SECURE-VMTP",
  83: "VINES",
  84: "TTP",
  84: "IPTM",
  85: "NSFNET-IGP",
  86: "DGP",
  87: "TCF",
  88: "EIGRP",
  89: "OSPFIGP",
  90: "Sprite-RPC",
  91: "LARP",
  92: "MTP",
  93: "AX.25",
  94: "IPIP",
  95: "MICP (deprecated)",
  96: "SCC-SP",
  97: "ETHERIP",
  98: "ENCAP",
  100: "GMTP",
  101: "IFMP",
  102: "PNNI",
  103: "PIM",
  104: "ARIS",
  105: "SCPS",
  106: "QNX",
  107: "A/N",
  108: "IPComp",
  109: "SNP",
  110: "Compaq-Peer",
  111: "IPX-in-IP",
  112: "VRRP",
  113: "PGM",
  115: "L2TP",
  116: "DDX",
  117: "IATP",
  118: "STP",
  119: "SRP",
  120: "UTI",
  121: "SMP",
  122: "SM (deprecated)",
  123: "PTP",
  124: "ISIS over IPv4",
  125: "FIRE",
  126: "CRTP",
  127: "CRUDP",
  128: "SSCOPMCE",
  129: "IPLT",
  130: "SPS",
  131: "PIPE",
  132: "SCTP",
  133: "FC",
  134: "RSVP-E2E-IGNORE",
  135: "Mobility Header",
  136: "UDPLite",
  137: "MPLS-in-IP",
  138: "manet",
  139: "HIP",
  140: "Shim6",
  141: "WESP",
  142: "ROHC",
  143: "Ethernet",
  255: "Reserved",
};

const sshConnectionOptions = {
  host: process.env.GW_HOST,
  port: 22,
  username: process.env.GW_USERNAME,
  password: process.env.GW_PASSWORD,
  algorithms: {
    kex: [
      "diffie-hellman-group-exchange-sha1",
      "diffie-hellman-group14-sha1",
      "diffie-hellman-group1-sha1",
    ],
    cipher: ["aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"],
  },
};

function handleConnectionClose(ssh) {
  const closeConnection = () => ssh.dispose();
  if (ssh.connection) {
    ssh.connection.on("error", closeConnection);
    ssh.connection.on("end", closeConnection);
  }
}

async function runCommand(command) {
  const ssh = new NodeSSH();
  await ssh.connect(sshConnectionOptions);
  handleConnectionClose(ssh);
  let strings = [];
  await ssh.execCommand(command, {
    onStdout: (chunk) => {
      strings.push(chunk.toString());
    },
  });
  if (strings.length > 1)
    return strings[1].replace(strings[0], "").split("\r\n");
  return undefined;
}

function formatHeaders(headers, pads) {
  return headers.map((header, index) =>
    header.toString().padEnd(pads[index], "\xa0")
  );
}

async function convertIpFlow(flow, pads) {
  const srcIpIndex = 1;
  const destIpIndex = 3;
  const protocolIndex = 4;
  const srcPortIndex = 5;
  const destPortIndex = 6;

  flow.pop();
  for (let i = 0; i < flow.length; i++) {
    let parts = flow[i].split(" ").filter((item) => item.length > 0);
    parts[srcIpIndex] = await resolveHostname(parts[srcIpIndex]);

    parts[destIpIndex] = await resolveHostname(parts[destIpIndex]);
    parts[protocolIndex] = protocols[parseInt(parts[protocolIndex])].padEnd(
      6,
      "\xa0"
    );
    parts[srcPortIndex] = parseInt(parts[srcPortIndex], 16).toString();
    parts[destPortIndex] = parseInt(parts[destPortIndex], 16).toString();
    parts = parts.map((item, index) => {
      return item.toString().padEnd(pads[index], "\xa0");
    });

    flow[i] = parts.join("");
  }
  return flow;
}

function filterIpFlow(flow) {
  return flow.filter((item) => {
    let parts = item.split("\xa0").filter((i) => i.length > 0);

    let bytes = parseInt(parts[parts.length - 1].toString().replace("K", ""));
    if (bytes >= (process.env.MAX_BYTES_K || 100)) return item;
    else return undefined;
  });
}

async function getIpFlow() {
  const command = "show ip cache flow | inc K";
  const pads = [14, MAX_HOSTNAME_LENGTH, 14, MAX_HOSTNAME_LENGTH, 8, 8, 8, 0];
  const headers = [
    "SrcIf",
    "SrcIPaddress",
    "DstIf",
    "DstIPaddress",
    "Pr",
    "SrcP",
    "DstP",
    "Bytes",
  ];
  let ipFlow = await runCommand(command);
  if (ipFlow) ipFlow = [...filterIpFlow(await convertIpFlow(ipFlow, pads))];
  else return undefined;

  if (ipFlow.length > 0) {
    let result = [
      `Bytes > ${process.env.MAX_BYTES_K || 100}K`,
      formatHeaders(headers, pads).join(""),
      ...ipFlow,
    ]
      .join("\r\n")
      .replace(" ", "\xa0");
    return result;
  } else return undefined;
}

async function clearIpFlow() {
  const commands = [
    "configure terminal; interface gigabitEthernet 0/0; no ip route-cache flow; exit; exit;",
    "configure terminal; interface gigabitEthernet 0/0; ip route-cache flow; exit; exit;",
  ];
  console.info(
    new Date().toLocaleString(),
    " Disable ip flow: ",
    await runCommand(commands[0])
  );
  await delay(1000 * 30);
  console.info(
    new Date().toLocaleString(),
    " Enable ip flow: ",
    await runCommand(commands[1])
  );
}

const sendTelegramMessagePlainText = async (message) => {
  const token = process.env.TG_BOT_TOKEN;
  const chat_id = process.env.TG_CHAT_ID;
  if (token && chat_id) {
    const formData = new FormData();
    formData.append("chat_id", chat_id);
    formData.append("parse_mode", "MarkdownV2");
    formData.append("text", message);

    const res = await (
      await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: "POST",
        body: formData,
      })
    ).json();
    console.info(res);
    return res;
  }
};

const sendTelegramPhotoFromBase64 = async (photo) => {
  const token = process.env.TG_BOT_TOKEN;
  const chat_id = process.env.TG_CHAT_ID;
  if (token && chat_id) {
    const blob = await (await fetch(photo)).blob();
    const formData = new FormData();
    formData.append("chat_id", chat_id);
    formData.append("photo", await (await fetch(photo)).blob());
    const res = await (
      await fetch(`https://api.telegram.org/bot${token}/sendPhoto`, {
        method: "POST",
        body: formData,
      })
    ).json();
    console.info(res);
    return res;
  }
};

const convertTextToImage = async (text) => {
  return await TextToImage.generate(text, {
    bgColor: "#212121",
    maxWidth: 1000,
    fontFamily: "monospace",
    textColor: "#e8e8e8",
    margin: 15,
    fontSize: 12,
  });
};

// main
async function ipFlow() {
  const ipFlow = await getIpFlow();
  if (ipFlow)
    await sendTelegramPhotoFromBase64(await convertTextToImage(ipFlow));
  await clearIpFlow();
}

async function main() {
  await ipFlow();
  setInterval(async () => await ipFlow(), 300 * 1000);
}
main();
