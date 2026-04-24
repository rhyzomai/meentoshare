import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.regex.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;

/**
 * ANT MEENTO GUI v4.2
 * P2P File Sharing · PKI Identity · Blockchain Ledger · DHT Bootstrap · HTTP Direct Download
 *
 * NEW IN v4.2:
 *  UPnP / NAT-PMP — at startup (and on every port change), performs a full
 *    SSDP multicast discovery, fetches the IGD device description XML, and
 *    issues a SOAP AddPortMapping + GetExternalIPAddress request — all in a
 *    background thread using only java.net.  On success the port badge shows
 *    the external WAN IP.  On failure the app continues normally (manual
 *    forwarding still works).  Pure Java, zero external libraries.
 *  IPv6 — parseHostPort now correctly handles [::1]:52525 bracket notation.
 *    isValidEntry accepts [hex:addr] and [hex:addr]:port entries.
 */
public class AntMeentoGui {

    // -- constants -------------------------------------------------------------
    private static final String SERVERS_FILE   = "servers.txt";
    private static final String DOWNLOAD_DIR   = "download";
    private static final String BLOCKCHAIN_DIR = "blockchain";
    private static final String IDENTITY_DIR   = "identity";
    private static final String PRIV_KEY_FILE  = "identity/private.key";
    private static final String PUB_KEY_FILE   = "identity/public.key";
    private static final String CHAIN_INDEX    = "blockchain/chain.index";
    private static final int    DEFAULT_PORT   = 52525;
    private static final int    POW_DIFF       = 2;

    /** DHT bootstrap URLs — fetched at launch to seed the peer list */
    private static final String[] DHT_BOOTSTRAP_URLS = {
        "http://meento.atwebpages.com/servers.php",
        "https://meentos.netlify.app/servers.txt",
        "https://meento.neocities.org/servers.txt",
        "https://geocities.ws/meento/servers.txt"
    };

    /** File extensions that mark a URL as a direct HTTP download target */
    private static final Set<String> HTTP_FILE_EXTS = new HashSet<String>(Arrays.asList(
        "jpg","jpeg","png","gif","bmp","webp","svg","ico",
        "mp4","mkv","avi","mov","wmv","flv","webm","m4v",
        "mp3","aac","ogg","flac","wav","opus","m4a",
        "pdf","doc","docx","xls","xlsx","ppt","pptx","odt","ods",
        "zip","tar","gz","bz2","xz","rar","7z","cab","deb","rpm",
        "exe","apk","dmg","iso","bin","img","msi",
        "txt","csv","json","xml","html","htm","md","log","ini","cfg","conf",
        "torrent","nfo","srt","ass","sub"
    ));

    // -- protocol tokens -------------------------------------------------------
    private static final String CMD_LIST         = "LIST";
    private static final String CMD_GET          = "GET";
    private static final String CMD_PUSH         = "PUSH";
    private static final String CMD_OK           = "OK";
    private static final String CMD_EXISTS       = "EXISTS";
    private static final String CMD_ERROR        = "ERROR";
    private static final String CMD_END          = "END";
    private static final String CMD_NOTIFY_BLOCK = "NOTIFY_BLOCK";
    private static final String CMD_GET_CHAIN    = "GET_CHAIN";
    private static final String CMD_PUBKEY       = "PUBKEY";
    private static final String CMD_REJECTED     = "REJECTED";

    // -- colours ---------------------------------------------------------------
    private static final Color C_BG      = new Color(0x0D,0x11,0x17);
    private static final Color C_PANEL   = new Color(0x13,0x19,0x21);
    private static final Color C_CARD    = new Color(0x1A,0x22,0x2E);
    private static final Color C_BORDER  = new Color(0x25,0x35,0x48);
    private static final Color C_ACCENT  = new Color(0x00,0xC8,0xFF);
    private static final Color C_ACCENT2 = new Color(0x00,0xFF,0xAA);
    private static final Color C_TEXT    = new Color(0xD0,0xE4,0xF4);
    private static final Color C_MUTED   = new Color(0x55,0x72,0x8A);
    private static final Color C_WARN    = new Color(0xFF,0xB8,0x00);
    private static final Color C_ERR     = new Color(0xFF,0x45,0x5A);
    private static final Color C_OK      = new Color(0x00,0xFF,0xAA);
    private static final Color C_ROWALT  = new Color(0x16,0x1E,0x28);
    private static final Color C_SRCH    = new Color(0xFF,0xD7,0x00);
    private static final Color C_CHAIN   = new Color(0xAA,0x88,0xFF);
    private static final Color C_HTTP    = new Color(0xFF,0x88,0x00);  // orange = HTTP entry

    // -- PKI -------------------------------------------------------------------
    private KeyPair myKeyPair;
    private String  myPublicKeyB64;
    private String  myFingerprint;

    // -- blockchain ------------------------------------------------------------
    private final Object      chainLock = new Object();
    private final List<Block> chain     = new ArrayList<Block>();

    // -- network ---------------------------------------------------------------
    private volatile int          port        = DEFAULT_PORT;
    private volatile ServerSocket serverSock  = null;
    private volatile boolean      receiveMode = true;
    private final ExecutorService pool        = Executors.newCachedThreadPool();

    // -- UPnP state ------------------------------------------------------------
    private volatile String  upnpExternalIp   = null;  // external IP reported by IGD
    private volatile boolean upnpMapped       = false; // true if port mapping succeeded
    private volatile String  upnpIgdUrl       = null;  // control URL of discovered IGD

    // -- DHT state -------------------------------------------------------------
    /** All entries loaded from local servers.txt + DHT bootstrap, runtime only */
    private final Set<String> dhtEntries    = Collections.synchronizedSet(new LinkedHashSet<String>());
    private       JLabel      dhtStatusLbl;

    // -- GUI refs --------------------------------------------------------------
    private JFrame            frame;
    private JTextPane         logPane;
    private JTable            filesTable, serversTable, searchTable, chainTable;
    private DefaultTableModel filesModel, serversModel, searchModel, chainModel;
    private JLabel            statusLabel, portLabel, fingerprintLabel, receiveModeLabel;
    private JLabel            searchStatusLbl, chainStatusLbl;
    private JProgressBar      syncProgress, searchProgress;
    private JButton           syncBtn, searchBtn;
    private JTextField        searchField;
    private JCheckBox         receiveModeCheck;
    /** search results: [filename, displaySource, host/url, portOrUrl, type] where type="p2p"|"http" */
    private final List<String[]> searchResultData = new ArrayList<String[]>();

    // -------------------------------------------------------------------------
    //  BLOCK (inner class)
    // -------------------------------------------------------------------------
    static class Block {
        String id, filename, sha256, senderPubKey, receiverPubKey;
        String senderSig, receiverSig, previousHash, hash;
        long   timestamp, filesize, nonce;

        String signingPayload() {
            return id+"|"+timestamp+"|"+filename+"|"+filesize+"|"+sha256
                  +"|"+senderPubKey+"|"+receiverPubKey+"|"+previousHash;
        }
        String toJson() {
            return "{\n"
              +"  \"id\": \""           +esc(id)             +"\",\n"
              +"  \"timestamp\": "      +timestamp            +",\n"
              +"  \"filename\": \""     +esc(filename)        +"\",\n"
              +"  \"filesize\": "       +filesize             +",\n"
              +"  \"sha256\": \""       +esc(sha256)          +"\",\n"
              +"  \"senderPubKey\": \"" +esc(senderPubKey)    +"\",\n"
              +"  \"receiverPubKey\": \""+esc(receiverPubKey) +"\",\n"
              +"  \"senderSig\": \""    +esc(senderSig)       +"\",\n"
              +"  \"receiverSig\": \""  +esc(receiverSig)     +"\",\n"
              +"  \"previousHash\": \"" +esc(previousHash)    +"\",\n"
              +"  \"nonce\": "          +nonce                +",\n"
              +"  \"hash\": \""         +esc(hash)            +"\"\n}";
        }
        private String esc(String s){return s==null?"":s.replace("\\","\\\\").replace("\"","\\\"");}
        static Block fromJson(String j){
            Block b=new Block();
            b.id=jStr(j,"id"); b.timestamp=jLong(j,"timestamp"); b.filename=jStr(j,"filename");
            b.filesize=jLong(j,"filesize"); b.sha256=jStr(j,"sha256");
            b.senderPubKey=jStr(j,"senderPubKey"); b.receiverPubKey=jStr(j,"receiverPubKey");
            b.senderSig=jStr(j,"senderSig"); b.receiverSig=jStr(j,"receiverSig");
            b.previousHash=jStr(j,"previousHash"); b.nonce=jLong(j,"nonce"); b.hash=jStr(j,"hash");
            return b;
        }
        private static String jStr(String j,String k){
            String p="\""+k+"\": \""; int i=j.indexOf(p); if(i<0)return "";
            int s=i+p.length(),e=s;
            while(e<j.length()){if(j.charAt(e)=='"'&&(e==0||j.charAt(e-1)!='\\'))break;e++;}
            return j.substring(s,e).replace("\\\"","\"").replace("\\\\","\\");
        }
        private static long jLong(String j,String k){
            String p="\""+k+"\": "; int i=j.indexOf(p); if(i<0)return 0;
            int s=i+p.length(),e=s;
            while(e<j.length()&&(Character.isDigit(j.charAt(e))||j.charAt(e)=='-'))e++;
            try{return Long.parseLong(j.substring(s,e));}catch(Exception x){return 0;}
        }
    }

    // -------------------------------------------------------------------------
    //  ENTRY POINT
    // -------------------------------------------------------------------------
    public static void main(String[] args){
        SwingUtilities.invokeLater(new Runnable(){public void run(){
            try{UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());}catch(Exception ig){}
            new AntMeentoGui().launch();
        }});
    }

    private void launch(){
        ensureDirs();
        loadOrCreateIdentity();
        loadChainFromDisk();
        buildUI();
        frame.setVisible(true);
        startServer();
        // UPnP / NAT-PMP hole punching — run in background, non-blocking
        pool.submit(new Runnable(){public void run(){doUPnP();}});
        // Load local servers into DHT runtime set
        dhtEntries.addAll(loadServers());
        // Bootstrap DHT in background — non-blocking
        pool.submit(new Runnable(){public void run(){bootstrapDHT();}});
        refreshFiles();
        refreshServers();
        refreshChainTable();
    }

    // -------------------------------------------------------------------------
    //  DHT BOOTSTRAP
    // -------------------------------------------------------------------------

    /**
     * Fetch each bootstrap URL, parse the lines, classify each as:
     *   - a p2p peer (host or host:port with no path/extension)
     *   - a direct http file URL (has a file extension)
     *   - another http/https URL without file extension ? treat as peer list, recurse once
     * Merges results into dhtEntries and saves new p2p peers into servers.txt.
     */
    private void bootstrapDHT(){
        log("DHT: contacting "+DHT_BOOTSTRAP_URLS.length+" bootstrap node(s)...", C_CHAIN);
        setDhtStatus("DHT: connecting...");
        int newPeers = 0;
        Set<String> discovered = new LinkedHashSet<String>();

        for(String bootstrapUrl : DHT_BOOTSTRAP_URLS){
            try{
                List<String> lines = fetchHttpLines(bootstrapUrl, 5000);
                log("DHT: "+bootstrapUrl+" ? "+lines.size()+" line(s)", C_MUTED);
                for(String line : lines){
                    line = line.trim();
                    if(line.isEmpty() || line.startsWith("#")) continue;
                    discovered.add(line);
                }
            }catch(Exception e){
                log("DHT: bootstrap failed ["+bootstrapUrl+"]: "+e.getMessage(), C_MUTED);
            }
        }

        // Merge into runtime set and persist new p2p peers to servers.txt
        Set<String> existingLocal = loadServers();
        int added = 0;
        for(String entry : discovered){
            if(!isValidEntry(entry)) continue; // skip malformed lines from bootstrap sources
            dhtEntries.add(entry);
            // Only persist plain p2p peers (no file extension at end) to servers.txt
            if(!isHttpFileUrl(entry) && !existingLocal.contains(entry)){
                existingLocal.add(entry);
                added++;
            }
        }
        if(added > 0){
            saveServers(existingLocal);
            log("DHT: "+added+" new peer(s) added to servers.txt", C_ACCENT2);
        }
        final int total = dhtEntries.size();
        final int peers = added;
        SwingUtilities.invokeLater(new Runnable(){public void run(){
            setDhtStatus("DHT: "+total+" entries ("+peers+" new peers)");
            refreshServers();
        }});
        log("DHT bootstrap complete. Total entries: "+total, C_CHAIN);
    }

    /** Fetch lines from an HTTP/HTTPS URL with a timeout */
    private List<String> fetchHttpLines(String urlStr, int timeoutMs) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs * 2);
        conn.setRequestProperty("User-Agent","AntMeento/4.0");
        conn.setInstanceFollowRedirects(true);
        int code = conn.getResponseCode();
        if(code < 200 || code >= 300) throw new IOException("HTTP "+code);
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        List<String> lines = new ArrayList<String>();
        String line;
        while((line = br.readLine()) != null) lines.add(line);
        br.close();
        conn.disconnect();
        return lines;
    }

    /** Download a file from an HTTP/HTTPS URL directly to the download folder */
    private boolean downloadHttpFile(String urlStr){
        try{
            String fname = extractFilenameFromUrl(urlStr);
            if(fname == null || fname.isEmpty()) fname = "download_"+System.currentTimeMillis();
            fname = sanitize(fname);
            File dest = new File(DOWNLOAD_DIR, fname);
            if(dest.exists()){ log("HTTP skip (exists): "+fname, C_MUTED); return false; }

            log("HTTP download: "+fname+" from "+urlStr, C_HTTP);
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(60000);
            conn.setRequestProperty("User-Agent","AntMeento/4.0");
            conn.setInstanceFollowRedirects(true);
            int code = conn.getResponseCode();
            if(code < 200 || code >= 300){
                log("HTTP "+code+" for "+urlStr, C_ERR); conn.disconnect(); return false;
            }
            InputStream is = conn.getInputStream();
            FileOutputStream fos = new FileOutputStream(dest);
            byte[] buf = new byte[8192]; int n;
            while((n=is.read(buf))!=-1) fos.write(buf,0,n);
            fos.close(); is.close(); conn.disconnect();

            log("HTTP downloaded: "+fname+" ("+humanSize(dest.length())+")", C_OK);
            // No blockchain record, no peer notification for plain HTTP downloads
            refreshFiles();
            return true;
        }catch(Exception e){
            log("HTTP error ["+urlStr+"]: "+e.getMessage(), C_ERR);
            return false;
        }
    }

    // -- URL classification helpers --------------------------------------------

    /** True if the entry is an http/https URL ending with a known file extension */
    private boolean isHttpFileUrl(String entry){
        if(!entry.toLowerCase().startsWith("http")) return false;
        String ext = getUrlFileExt(entry);
        return ext != null && HTTP_FILE_EXTS.contains(ext.toLowerCase());
    }

    /**
     * True if this http/https URL has an EXPLICIT P2P port (i.e. the default
     * port or any custom numeric port embedded in the URL).  Those should be
     * routed through the normal P2P stack.
     */
    private boolean isHttpWithP2PPort(String entry){
        if(!entry.toLowerCase().startsWith("http")) return false;
        try{
            URL u = new URL(entry);
            int p = u.getPort();
            // -1 means no explicit port was given (standard 80/443)
            return p == port || (p != -1 && p != 80 && p != 443);
        }catch(Exception e){ return false; }
    }

    /** True if the entry is a plain http/https URL with no P2P port and no file ext */
    private boolean isHttpPeerListUrl(String entry){
        if(!entry.toLowerCase().startsWith("http")) return false;
        return !isHttpFileUrl(entry) && !isHttpWithP2PPort(entry);
    }

    /** Extract file extension from a URL path, null if none */
    private String getUrlFileExt(String urlStr){
        try{
            String path = new URL(urlStr).getPath();
            int dot = path.lastIndexOf('.');
            int slash = path.lastIndexOf('/');
            if(dot > slash && dot < path.length()-1) return path.substring(dot+1).toLowerCase();
        }catch(Exception ignored){}
        return null;
    }

    /** Extract the filename from a URL path */
    private String extractFilenameFromUrl(String urlStr){
        try{
            String path = new URL(urlStr).getPath();
            int slash = path.lastIndexOf('/');
            return slash >= 0 ? path.substring(slash+1) : path;
        }catch(Exception e){ return null; }
    }

    /**
     * Resolve a server entry to p2p [host, port] or null if it is not a p2p entry.
     * HTTP entries with a P2P port are resolved by extracting host+port from the URL.
     */
    private String[] entryToP2P(String entry){
        if(entry == null || entry.isEmpty()) return null;
        // Plain URL with P2P port ? extract host:port, treat as p2p
        if(entry.toLowerCase().startsWith("http") && isHttpWithP2PPort(entry)){
            try{
                URL u = new URL(entry);
                return new String[]{ u.getHost(), String.valueOf(u.getPort()) };
            }catch(Exception e){ return null; }
        }
        // Plain http URL without p2p port ? not a p2p entry
        if(entry.toLowerCase().startsWith("http")) return null;
        // host or host:port
        return parseHostPort(entry);
    }

    /**
     * Parse a raw host[:port] entry into [host, port].
     * Handles four formats:
     *   IPv6 with port   — [::1]:52525   ? ["::1",  "52525"]
     *   IPv6 bare        — [::1]         ? ["::1",  "52525"]
     *   IPv4/hostname    — host.com:1234 ? ["host.com", "1234"]
     *   bare hostname    — host.com      ? ["host.com", "52525"]
     */
    private String[] parseHostPort(String raw){
        try{
            String s = raw.trim();
            // IPv6 address in brackets: [addr] or [addr]:port
            if(s.startsWith("[")){
                int closeBracket = s.indexOf(']');
                if(closeBracket < 0) return null; // malformed
                String host = s.substring(1, closeBracket);  // strip [ ]
                if(closeBracket + 1 < s.length() && s.charAt(closeBracket+1) == ':'){
                    String portStr = s.substring(closeBracket+2);
                    return new String[]{host, portStr};
                }
                return new String[]{host, String.valueOf(DEFAULT_PORT)};
            }
            // IPv4 or hostname with optional port — use last colon as separator
            if(s.contains(":")){
                String h = s.substring(0, s.lastIndexOf(':'));
                String p = s.substring(s.lastIndexOf(':')+1);
                return new String[]{h, p};
            }
            return new String[]{s, String.valueOf(DEFAULT_PORT)};
        }catch(Exception e){ log("Bad entry: "+raw, C_ERR); return null; }
    }

    /**
     * Validate a server entry before insertion.
     * Accepts:
     *   - http:// or https:// URLs (basic URL syntax check)
     *   - IPv4 addresses (with optional :port)
     *   - Hostnames composed only of alphanumerics, dots, hyphens (with optional :port)
     * Rejects anything containing whitespace, HTML tags, angle brackets, or
     * entries that are clearly just plain prose (no dot, no colon, no slash).
     */
    private boolean isValidEntry(String raw){
        if(raw == null) return false;
        String s = raw.trim();
        if(s.isEmpty()) return false;
        // Reject if contains HTML / angle brackets / obvious bad chars
        if(s.contains("<") || s.contains(">") || s.contains("\"") || s.contains("'")
                || s.contains(" ") || s.contains("\t")) return false;
        // Accept http/https URLs — validate with java.net.URL
        if(s.toLowerCase().startsWith("http://") || s.toLowerCase().startsWith("https://")){
            try{
                URL u = new URL(s);
                String host = u.getHost();
                // Host must be non-empty and contain at least one dot or be localhost/IP
                if(host == null || host.isEmpty()) return false;
                if(!host.contains(".") && !host.equalsIgnoreCase("localhost")) return false;
                // Host must not contain forbidden chars
                if(host.matches(".*[<>\\s\"'].*")) return false;
                return true;
            }catch(Exception e){ return false; }
        }
        // Accept host:port or bare hostname/IP
        // Must match: (letters/digits/dots/hyphens/brackets for IPv6) with optional :port
        String hostPart = s.contains(":") ? s.substring(0, s.lastIndexOf(':')) : s;
        String portPart = s.contains(":") ? s.substring(s.lastIndexOf(':')+1) : null;
        // IPv6 bracket form [addr] or [addr]:port
        if(s.startsWith("[")){
            int cb = s.indexOf(']');
            if(cb < 0) return false;
            String addr = s.substring(1, cb);
            if(addr.isEmpty()) return false;
            if(!addr.matches("[0-9a-fA-F:]+")) return false; // must be hex digits and colons
            if(cb+1 < s.length()){
                if(s.charAt(cb+1) != ':') return false;
                try{ int p=Integer.parseInt(s.substring(cb+2)); if(p<1||p>65535) return false; }
                catch(NumberFormatException e){ return false; }
            }
            return true;
        }
        // hostPart must look like a hostname or IP (has a dot, or is pure digits separated by dots)
        if(!hostPart.matches("[a-zA-Z0-9.\\-\\[\\]:]+")) return false;
        // Must contain a dot (to distinguish from bare keywords like "hello")
        if(!hostPart.contains(".") && !hostPart.equalsIgnoreCase("localhost")) return false;
        // portPart if present must be a valid number
        if(portPart != null){
            try{ int p=Integer.parseInt(portPart); if(p<1||p>65535) return false; }
            catch(NumberFormatException e){ return false; }
        }
        return true;
    }

    /**
     * Returns true if this server entry should receive an HTTP GET ?info= notification
     * after a successful P2P transfer.  Qualifies when the URL ends with .php
     * or when its path ends with /info (with or without trailing slash).
     */
    private boolean isInfoNotifyUrl(String entry){
        if(entry == null) return false;
        String lo = entry.toLowerCase().trim();
        if(!lo.startsWith("http")) return false;
        try{
            String path = new URL(entry).getPath();
            String lp = path.toLowerCase();
            return lp.endsWith(".php") || lp.endsWith("/info") || lp.equals("/info");
        }catch(Exception e){ return false; }
    }

    private void setDhtStatus(final String msg){
        SwingUtilities.invokeLater(new Runnable(){public void run(){
            if(dhtStatusLbl!=null) dhtStatusLbl.setText("  "+msg);
        }});
    }

    // -------------------------------------------------------------------------
    //  PKI
    // -------------------------------------------------------------------------
    private void loadOrCreateIdentity(){
        File prv=new File(PRIV_KEY_FILE), pub=new File(PUB_KEY_FILE);
        if(prv.exists()&&pub.exists()){
            try{
                KeyFactory kf=KeyFactory.getInstance("RSA");
                byte[] prvB=Base64.getDecoder().decode(readTxt(prv).trim());
                byte[] pubB=Base64.getDecoder().decode(readTxt(pub).trim());
                PrivateKey pr=kf.generatePrivate(new PKCS8EncodedKeySpec(prvB));
                PublicKey  pu=kf.generatePublic(new X509EncodedKeySpec(pubB));
                myKeyPair=new KeyPair(pu,pr);
                myPublicKeyB64=Base64.getEncoder().encodeToString(pu.getEncoded());
                myFingerprint=fingerprint(pu.getEncoded());
                System.out.println("[identity] Loaded. FP="+myFingerprint); return;
            }catch(Exception e){System.out.println("[identity] Reload failed, regenerating: "+e.getMessage());}
        }
        try{
            KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");
            g.initialize(2048,new SecureRandom());
            myKeyPair=g.generateKeyPair();
            myPublicKeyB64=Base64.getEncoder().encodeToString(myKeyPair.getPublic().getEncoded());
            myFingerprint=fingerprint(myKeyPair.getPublic().getEncoded());
            writeTxt(new File(PRIV_KEY_FILE),Base64.getEncoder().encodeToString(myKeyPair.getPrivate().getEncoded()));
            writeTxt(new File(PUB_KEY_FILE),myPublicKeyB64);
            System.out.println("[identity] Generated. FP="+myFingerprint);
        }catch(Exception e){throw new RuntimeException("PKI init failed",e);}
    }
    private String fingerprint(byte[] kb) throws Exception{
        byte[] h=MessageDigest.getInstance("SHA-256").digest(kb);
        StringBuilder sb=new StringBuilder();
        for(int i=0;i<8;i++) sb.append(String.format("%02X",h[i]));
        return sb.toString();
    }
    private String sign(byte[] data) throws Exception{
        Signature s=Signature.getInstance("SHA256withRSA");
        s.initSign(myKeyPair.getPrivate()); s.update(data);
        return Base64.getEncoder().encodeToString(s.sign());
    }
    private boolean verify(byte[] data, String sigB64, String pubB64){
        try{
            KeyFactory kf=KeyFactory.getInstance("RSA");
            PublicKey pk=kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pubB64)));
            Signature s=Signature.getInstance("SHA256withRSA");
            s.initVerify(pk); s.update(data);
            return s.verify(Base64.getDecoder().decode(sigB64));
        }catch(Exception e){return false;}
    }
    private String fetchRemotePubKey(String host, int rp){
        try{
            Socket s=connect(host,rp); if(s==null)return null;
            PrintWriter out=new PrintWriter(s.getOutputStream(),true);
            BufferedReader in=new BufferedReader(new InputStreamReader(s.getInputStream()));
            out.println(CMD_PUBKEY); String r=in.readLine(); s.close();
            if(r!=null&&r.startsWith(CMD_OK+" "))return r.substring(CMD_OK.length()+1).trim();
        }catch(Exception ig){}
        return null;
    }

    // -------------------------------------------------------------------------
    //  BLOCKCHAIN
    // -------------------------------------------------------------------------
    private String sha256hex(String s) throws Exception{
        byte[] h=MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb=new StringBuilder(); for(byte b:h)sb.append(String.format("%02x",b)); return sb.toString();
    }
    private String sha256file(File f) throws Exception{
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        try(FileInputStream fi=new FileInputStream(f)){byte[]buf=new byte[8192];int n;while((n=fi.read(buf))!=-1)md.update(buf,0,n);}
        StringBuilder sb=new StringBuilder(); for(byte b:md.digest())sb.append(String.format("%02x",b)); return sb.toString();
    }
    private Block createAndPublishBlock(File file, String senderPub, String senderSigParam){
        try{
            String prevHash; synchronized(chainLock){prevHash=chain.isEmpty()?"GENESIS":chain.get(chain.size()-1).hash;}
            Block b=new Block();
            b.id=UUID.randomUUID().toString(); b.timestamp=System.currentTimeMillis();
            b.filename=file.getName(); b.filesize=file.length(); b.sha256=sha256file(file);
            b.senderPubKey=senderPub!=null&&!senderPub.isEmpty()?senderPub:"UNKNOWN";
            b.receiverPubKey=myPublicKeyB64; b.previousHash=prevHash;
            b.senderSig=senderSigParam!=null?senderSigParam:"";
            b.receiverSig=sign(b.signingPayload().getBytes(StandardCharsets.UTF_8));
            String pfx="0".repeat(POW_DIFF); long nonce=0; String h;
            do{ h=sha256hex(b.toJson()+nonce); if(!h.startsWith(pfx))nonce++; else break; }while(true);
            b.nonce=nonce; b.hash=h;
            appendBlockToDisk(b); synchronized(chainLock){chain.add(b);}
            log("Block #"+chain.size()+" mined ["+b.hash.substring(0,12)+"...]",C_CHAIN);
            broadcastBlock(b); refreshChainTable();
            return b;
        }catch(Exception e){log("Block creation failed: "+e.getMessage(),C_ERR);return null;}
    }
    private boolean validateBlock(Block b){
        try{
            if(!b.hash.startsWith("0".repeat(POW_DIFF))){log("Block invalid: PoW",C_ERR);return false;}
            synchronized(chainLock){
                if(!chain.isEmpty()){String ep=chain.get(chain.size()-1).hash;
                    if(!ep.equals(b.previousHash)){log("Block invalid: chain link",C_WARN);return false;}}
            }
            if(!b.receiverSig.isEmpty()&&!b.receiverPubKey.isEmpty()){
                if(!verify(b.signingPayload().getBytes(StandardCharsets.UTF_8),b.receiverSig,b.receiverPubKey)){log("Block invalid: receiver sig",C_ERR);return false;}}
            if(!b.senderSig.isEmpty()&&!b.senderPubKey.isEmpty()&&!"UNKNOWN".equals(b.senderPubKey)){
                if(!verify(b.signingPayload().getBytes(StandardCharsets.UTF_8),b.senderSig,b.senderPubKey)){log("Block invalid: sender sig",C_ERR);return false;}}
            return true;
        }catch(Exception e){log("Validation error: "+e.getMessage(),C_ERR);return false;}
    }
    private void broadcastBlock(final Block b){
        for(final String entry:new LinkedHashSet<String>(loadServers())){
            final String[] hp = entryToP2P(entry);
            if(hp==null) continue; // skip http entries without p2p port
            pool.submit(new Runnable(){public void run(){
                try{Socket s=connect(hp[0],Integer.parseInt(hp[1]));if(s==null)return;
                    PrintWriter out=new PrintWriter(s.getOutputStream(),true);
                    BufferedReader in=new BufferedReader(new InputStreamReader(s.getInputStream()));
                    out.println(CMD_NOTIFY_BLOCK+" "+b.toJson().replace("\n","\\n"));
                    String r=in.readLine(); s.close();
                    log("Block "+(CMD_OK.equals(r)?"accepted":"rejected")+" by "+hp[0],C_CHAIN);
                }catch(Exception ig){}
            }});
        }
    }
    private void appendBlockToDisk(Block b) throws Exception{
        new File(BLOCKCHAIN_DIR).mkdirs();
        writeTxt(new File(BLOCKCHAIN_DIR,b.id+".json"),b.toJson());
        try(FileWriter fw=new FileWriter(CHAIN_INDEX,true)){fw.write(b.id+"\n");}
    }
    private void loadChainFromDisk(){
        File idx=new File(CHAIN_INDEX); if(!idx.exists())return;
        try(BufferedReader br=new BufferedReader(new FileReader(idx))){
            String id; while((id=br.readLine())!=null){
                id=id.trim(); if(id.isEmpty())continue;
                File bf=new File(BLOCKCHAIN_DIR,id+".json"); if(!bf.exists())continue;
                chain.add(Block.fromJson(readTxt(bf)));
            }
            log("Loaded "+chain.size()+" block(s) from ledger.",C_CHAIN);
        }catch(Exception e){log("Error loading chain: "+e.getMessage(),C_ERR);}
    }
    private void verifyFullChain(){
        pool.submit(new Runnable(){public void run(){
            List<Block> snap; synchronized(chainLock){snap=new ArrayList<Block>(chain);}
            if(snap.isEmpty()){log("Chain is empty.",C_WARN);return;}
            boolean ok=true;
            for(int i=0;i<snap.size();i++){Block b=snap.get(i);
                if(!b.hash.startsWith("0".repeat(POW_DIFF))){log("Block #"+(i+1)+" FAIL: PoW",C_ERR);ok=false;continue;}
                if(i>0&&!snap.get(i-1).hash.equals(b.previousHash)){log("Block #"+(i+1)+" FAIL: chain link",C_ERR);ok=false;continue;}
                if(!b.receiverSig.isEmpty()&&!b.receiverPubKey.isEmpty()){
                    if(!verify(b.signingPayload().getBytes(StandardCharsets.UTF_8),b.receiverSig,b.receiverPubKey)){log("Block #"+(i+1)+" FAIL: sig",C_ERR);ok=false;continue;}}
                log("Block #"+(i+1)+" \u2714 ["+b.hash.substring(0,10)+"...]",C_OK);}
            log(ok?"Chain VERIFIED \u2714 — "+snap.size()+" blocks OK":"Chain has INVALID blocks \u2718",ok?C_ACCENT2:C_ERR);
        }});
    }
    private void syncChainFromPeers(){
        Set<String> srvs=loadServers(); if(srvs.isEmpty()){log("No peers.",C_WARN);return;}
        log("Syncing chain from peers...",C_CHAIN);
        List<List<Block>> all=new ArrayList<List<Block>>();
        for(String u:srvs){String[]hp=entryToP2P(u);if(hp==null)continue;List<Block>pc=fetchChainFromPeer(hp[0],Integer.parseInt(hp[1]));if(!pc.isEmpty())all.add(pc);}
        List<Block> longest=null;
        for(List<Block>pc:all)if(validChain(pc)&&(longest==null||pc.size()>longest.size()))longest=pc;
        if(longest!=null&&longest.size()>chain.size()){
            synchronized(chainLock){chain.clear();chain.addAll(longest);}
            try{new File(CHAIN_INDEX).delete();for(Block b:longest)appendBlockToDisk(b);}catch(Exception e){log("Save chain error: "+e.getMessage(),C_ERR);}
            log("Chain updated: "+longest.size()+" blocks.",C_CHAIN); refreshChainTable();
        }else{log("Chain up-to-date ("+chain.size()+" blocks).",C_OK);}
    }
    private boolean validChain(List<Block> bl){
        for(int i=0;i<bl.size();i++){Block b=bl.get(i);
            if(!b.hash.startsWith("0".repeat(POW_DIFF)))return false;
            if(i>0&&!bl.get(i-1).hash.equals(b.previousHash))return false;}
        return true;
    }
    private List<Block> fetchChainFromPeer(String host, int rp){
        List<Block> r=new ArrayList<Block>();
        try{Socket s=connect(host,rp);if(s==null)return r;
            PrintWriter out=new PrintWriter(s.getOutputStream(),true);
            BufferedReader in=new BufferedReader(new InputStreamReader(s.getInputStream()));
            out.println(CMD_GET_CHAIN); String line;
            while((line=in.readLine())!=null&&!line.equals(CMD_END)){Block b=Block.fromJson(line.replace("\\n","\n"));if(b.id!=null&&!b.id.isEmpty())r.add(b);}
            s.close();
        }catch(Exception ig){}
        return r;
    }

    // -------------------------------------------------------------------------
    //  SYNC — handles both P2P peers and HTTP file URLs
    // -------------------------------------------------------------------------
    private void syncAll(){
        // Combine local servers + DHT runtime entries
        Set<String> allEntries = new LinkedHashSet<String>(loadServers());
        allEntries.addAll(dhtEntries);
        if(allEntries.isEmpty()){log("No servers/entries configured.",C_WARN);return;}
        setSyncRunning(true);
        log("Sync starting — "+allEntries.size()+" entries...",C_ACCENT);
        List<Future<?>> ts=new ArrayList<Future<?>>();
        for(final String entry : allEntries){
            ts.add(pool.submit(new Runnable(){public void run(){
                if(isHttpFileUrl(entry) && !isHttpWithP2PPort(entry)){
                    // Direct HTTP file — download silently, no blockchain
                    downloadHttpFile(entry);
                } else if(isHttpPeerListUrl(entry)){
                    // It's a peer-list URL — fetch and sync each peer inside it
                    try{
                        List<String> lines = fetchHttpLines(entry, 5000);
                        for(String line : lines){
                            line=line.trim(); if(line.isEmpty()||line.startsWith("#"))continue;
                            String[]hp=entryToP2P(line);
                            if(hp!=null) syncWithP2P(hp[0],Integer.parseInt(hp[1]));
                        }
                    }catch(Exception e){log("Peer-list fetch error ["+entry+"]: "+e.getMessage(),C_MUTED);}
                } else {
                    // P2P peer
                    String[]hp=entryToP2P(entry);
                    if(hp!=null) syncWithP2P(hp[0],Integer.parseInt(hp[1]));
                }
            }}));
        }
        for(Future<?> t:ts)try{t.get();}catch(Exception e){log("Sync error: "+e.getMessage(),C_ERR);}
        log("Sync complete.",C_ACCENT2); setSyncRunning(false); refreshFiles();
    }

    private void syncWithP2P(String host, int rp){
        log("P2P sync ? "+host+":"+rp,C_MUTED);
        List<String> remote=listRemoteFiles(host,rp); if(remote.isEmpty())return;
        Set<String> local=new HashSet<String>(localFileNames());
        for(String n:remote)if(!local.contains(n))downloadFileP2P(host,rp,n);
        Set<String> rs=new HashSet<String>(remote);
        for(String n:local)if(!rs.contains(n))pushFile(host,rp,n);
    }

    // -------------------------------------------------------------------------
    //  P2P SERVER
    // -------------------------------------------------------------------------
    private void startServer(){
        pool.submit(new Runnable(){public void run(){
            try{serverSock=new ServerSocket(port);
                log("Server listening on port "+port,C_OK);
                SwingUtilities.invokeLater(new Runnable(){public void run(){portLabel.setText("\u25CF  :"+port);portLabel.setForeground(C_OK);}});
                setStatus("Port "+port+"  |  ID: "+myFingerprint);
                while(!serverSock.isClosed()){
                    try{final Socket cl=serverSock.accept();pool.submit(new Runnable(){public void run(){handleIncoming(cl);}});}
                    catch(SocketException e){if(!serverSock.isClosed())log("Socket error: "+e.getMessage(),C_ERR);}}
            }catch(IOException e){log("Server failed: "+e.getMessage(),C_ERR);
                SwingUtilities.invokeLater(new Runnable(){public void run(){portLabel.setText("\u25CF  OFFLINE");portLabel.setForeground(C_ERR);}});}
        }});
    }
    private void restartServer(){
        try{if(serverSock!=null&&!serverSock.isClosed())serverSock.close();}catch(IOException ig){}
        SwingUtilities.invokeLater(new Runnable(){public void run(){portLabel.setText("\u25CF  ...");portLabel.setForeground(C_WARN);}});
        startServer();
        // Re-map the new port via UPnP
        pool.submit(new Runnable(){public void run(){doUPnP();}});
    }
    private void handleIncoming(Socket sock){
        String peer=sock.getRemoteSocketAddress().toString();
        try{
            BufferedReader in=new BufferedReader(new InputStreamReader(sock.getInputStream()));
            PrintWriter out=new PrintWriter(new OutputStreamWriter(sock.getOutputStream()),true);
            String line=in.readLine(); if(line==null){sock.close();return;}
            if(line.startsWith(CMD_LIST)){
                for(String f:localFileNames())out.println(f); out.println(CMD_END);
            }else if(line.startsWith(CMD_PUBKEY)){
                out.println(CMD_OK+" "+myPublicKeyB64);
            }else if(line.startsWith(CMD_GET+" ")){
                String name=line.substring(CMD_GET.length()+1).trim();
                File file=new File(DOWNLOAD_DIR,sanitize(name));
                if(!file.exists()||!file.isFile()){out.println(CMD_ERROR+" not found");sock.close();return;}
                out.println(CMD_OK+" "+file.length()); out.flush();
                InputStream fis=new FileInputStream(file); OutputStream os=sock.getOutputStream();
                byte[]buf=new byte[8192];int n; while((n=fis.read(buf))!=-1)os.write(buf,0,n);
                os.flush(); fis.close();
            }else if(line.startsWith(CMD_PUSH+" ")){
                if(!receiveMode){out.println(CMD_REJECTED+" receive-mode-off");log("Rejected push (mode OFF) from "+peer,C_WARN);sock.close();return;}
                String[]pts=line.split(" ",4);
                if(pts.length<3){out.println(CMD_ERROR+" bad header");sock.close();return;}
                String name=sanitize(pts[1]); long length;
                try{length=Long.parseLong(pts[2]);}catch(NumberFormatException e){out.println(CMD_ERROR+" bad length");sock.close();return;}
                String sndPub=pts.length>=4?pts[3]:"UNKNOWN";
                File dest=new File(DOWNLOAD_DIR,name);
                if(dest.exists()){out.println(CMD_EXISTS);sock.close();return;}
                out.println(CMD_OK); out.flush();
                receiveFile(sock.getInputStream(),dest,length);
                log("Received '"+name+"' from "+peer,C_OK);
                final File df=dest; final String sp=sndPub;
                pool.submit(new Runnable(){public void run(){createAndPublishBlock(df,sp,"");refreshFiles();}});
            }else if(line.startsWith(CMD_NOTIFY_BLOCK+" ")){
                String json=line.substring(CMD_NOTIFY_BLOCK.length()+1).replace("\\n","\n");
                Block b=Block.fromJson(json);
                if(validateBlock(b)){appendBlockToDisk(b);synchronized(chainLock){chain.add(b);}
                    out.println(CMD_OK);log("Accepted block from "+peer+" ["+b.hash.substring(0,10)+"...]",C_CHAIN);refreshChainTable();}
                else{out.println(CMD_ERROR+" invalid-block");}
            }else if(line.startsWith(CMD_GET_CHAIN)){
                List<Block> snap; synchronized(chainLock){snap=new ArrayList<Block>(chain);}
                for(Block b:snap)out.println(b.toJson().replace("\n","\\n")); out.println(CMD_END);
            }else{out.println(CMD_ERROR+" unknown");}
            sock.close();
        }catch(Exception e){log("Peer error ["+peer+"]: "+e.getMessage(),C_ERR);try{sock.close();}catch(IOException ig){}}
    }

    // -------------------------------------------------------------------------
    //  P2P CLIENT
    // -------------------------------------------------------------------------
    private void downloadFileP2P(String host, int rp, String name){
        File dest=new File(DOWNLOAD_DIR,name); if(dest.exists())return;
        try{Socket s=connect(host,rp); if(s==null)return;
            PrintWriter out=new PrintWriter(s.getOutputStream(),true);
            BufferedReader in=new BufferedReader(new InputStreamReader(s.getInputStream()));
            out.println(CMD_GET+" "+name); String resp=in.readLine();
            if(resp==null||!resp.startsWith(CMD_OK)){log("Refused '"+name+"': "+resp,C_WARN);s.close();return;}
            long len=Long.parseLong(resp.split(" ")[1]); out.flush();
            receiveFile(s.getInputStream(),dest,len); s.close();
            log("Downloaded: "+name+" ("+humanSize(len)+")",C_OK);
            final File df=dest; final String rh=host; final int rport=rp;
            pool.submit(new Runnable(){public void run(){String sp=fetchRemotePubKey(rh,rport);createAndPublishBlock(df,sp,"");refreshFiles();}});
            notifyInfoEndpoints(dest, host);
        }catch(Exception e){log("Error downloading '"+name+"': "+e.getMessage(),C_ERR);new File(DOWNLOAD_DIR,name).delete();}
    }
    private void pushFile(String host, int rp, String name){
        File src=new File(DOWNLOAD_DIR,name); if(!src.exists())return;
        try{Socket s=connect(host,rp); if(s==null)return;
            OutputStream raw=s.getOutputStream();
            PrintWriter out=new PrintWriter(new OutputStreamWriter(raw),true);
            BufferedReader in=new BufferedReader(new InputStreamReader(s.getInputStream()));
            out.println(CMD_PUSH+" "+name+" "+src.length()+" "+myPublicKeyB64); out.flush();
            String resp=in.readLine();
            if(CMD_EXISTS.equals(resp)){s.close();return;}
            if(resp!=null&&resp.startsWith(CMD_REJECTED)){log("Push rejected by "+host+" (receive mode OFF)",C_WARN);s.close();return;}
            if(!CMD_OK.equals(resp)){log("Push refused: "+resp,C_WARN);s.close();return;}
            FileInputStream fis=new FileInputStream(src); byte[]buf=new byte[8192];int n;
            while((n=fis.read(buf))!=-1)raw.write(buf,0,n); raw.flush(); fis.close(); s.close();
            log("Sent: "+name+" \u2192 "+host,C_ACCENT);
        }catch(Exception e){log("Error pushing '"+name+"': "+e.getMessage(),C_ERR);}
    }
    private List<String> listRemoteFiles(String host, int rp){
        List<String> r=new ArrayList<String>();
        try{Socket s=new Socket();s.connect(new InetSocketAddress(host,rp),5000);s.setSoTimeout(15000);
            PrintWriter out=new PrintWriter(s.getOutputStream(),true);
            BufferedReader in=new BufferedReader(new InputStreamReader(s.getInputStream()));
            out.println(CMD_LIST); String line;
            while((line=in.readLine())!=null&&!line.equals(CMD_END))r.add(line.trim());
            s.close();}catch(Exception e){log("Cannot list "+host+":"+rp+" — "+e.getMessage(),C_MUTED);}
        return r;
    }

    /**
     * After a successful P2P transfer, notify all servers whose URL ends with
     * ".php" or "/info" by sending an HTTP GET request with an "info" query
     * parameter containing JSON-encoded transfer metadata.
     * HTTP file entries (those without a P2P port) are intentionally excluded.
     */
    private void notifyInfoEndpoints(final File file, final String senderHost){
        pool.submit(new Runnable(){public void run(){
            Set<String> all = new LinkedHashSet<String>(loadServers());
            all.addAll(dhtEntries);
            for(String entry : all){
                if(!isInfoNotifyUrl(entry)) continue;
                try{
                    String sha = "";
                    try{sha = sha256file(file);}catch(Exception ig){}
                    // Fetch the public key of the peer we downloaded from
                    String serverPubKey = "";
                    try{
                        String[] hp = parseHostPort(senderHost);
                        if(hp != null){
                            String fetched = fetchRemotePubKey(hp[0], Integer.parseInt(hp[1]));
                            if(fetched != null) serverPubKey = fetched;
                        }
                    }catch(Exception ig){}
                    // Build JSON info payload (URL-encoded)
                    String json = "{"
                        +"\"filename\":\""+file.getName()+"\","
                        +"\"filesize\":"+file.length()+","
                        +"\"sha256\":\""+sha+"\","
                        +"\"senderPubKey\":\""+myPublicKeyB64+"\","
                        +"\"serverPubKey\":\""+serverPubKey+"\","
                        +"\"receiver\":\""+myFingerprint+"\","
                        +"\"timestamp\":"+System.currentTimeMillis()
                        +"}";
                    String encoded = URLEncoder.encode(json, "UTF-8");
                    // Append ?info=... to the base URL
                    String base = entry.contains("?") ? entry+"&info="+encoded : entry+"?info="+encoded;
                    URL url = new URL(base);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setConnectTimeout(5000);
                    conn.setReadTimeout(8000);
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("User-Agent","AntMeento/4.0");
                    int code = conn.getResponseCode();
                    conn.disconnect();
                    log("Info notify ["+entry+"]: HTTP "+code, code>=200&&code<300 ? C_MUTED : C_WARN);
                }catch(Exception e){
                    log("Info notify failed ["+entry+"]: "+e.getMessage(), C_MUTED);
                }
            }
        }});
    }

    // -------------------------------------------------------------------------
    //  SEARCH — searches P2P peers AND http file entries
    // -------------------------------------------------------------------------
    private void doSearch(){
        final String q=searchField.getText().trim().toLowerCase();
        if(q.isEmpty()){searchStatusLbl.setText("  Enter a term first.");return;}

        // Combine local + DHT
        final Set<String> allEntries = new LinkedHashSet<String>(loadServers());
        allEntries.addAll(dhtEntries);
        if(allEntries.isEmpty()){searchStatusLbl.setText("  No servers/entries.");log("Search: nothing to search.",C_WARN);return;}

        SwingUtilities.invokeLater(new Runnable(){public void run(){
            searchModel.setRowCount(0); searchResultData.clear();
            searchBtn.setEnabled(false); searchProgress.setVisible(true);
            searchStatusLbl.setText("  Searching "+allEntries.size()+" entries...");
        }});

        pool.submit(new Runnable(){public void run(){
            for(final String entry : allEntries){
                // -- HTTP file URL ------------------------------------------
                if(isHttpFileUrl(entry) && !isHttpWithP2PPort(entry)){
                    String fname = extractFilenameFromUrl(entry);
                    // Match on filename OR on the full URL string
                    boolean fnMatch  = fname != null && !fname.isEmpty() && fname.toLowerCase().contains(q);
                    boolean urlMatch = entry.toLowerCase().contains(q);
                    if(fnMatch || urlMatch){
                        final String displayName = (fname != null && !fname.isEmpty()) ? fname : entry;
                        final boolean have = new File(DOWNLOAD_DIR, sanitize(displayName)).exists();
                        final String fn = displayName;
                        SwingUtilities.invokeLater(new Runnable(){public void run(){
                            searchResultData.add(new String[]{fn, entry, entry, "", "http"});
                            searchModel.addRow(new Object[]{
                                "  "+fn, "  \uD83C\uDF10 "+entry, have?"Already have":"HTTP"});
                        }});
                    }
                    continue;
                }
                // -- HTTP peer-list URL — fetch and search files inside -----
                if(isHttpPeerListUrl(entry)){
                    try{
                        List<String> lines = fetchHttpLines(entry, 5000);
                        for(String line : lines){
                            line=line.trim(); if(line.isEmpty()||line.startsWith("#"))continue;
                            // Sub-entry could be another http file url
                            if(isHttpFileUrl(line) && !isHttpWithP2PPort(line)){
                                String fn=extractFilenameFromUrl(line);
                                // Match on filename OR full URL
                                boolean fnM  = fn!=null&&!fn.isEmpty()&&fn.toLowerCase().contains(q);
                                boolean urlM = line.toLowerCase().contains(q);
                                if(fnM || urlM){
                                    final String dispName = (fn!=null&&!fn.isEmpty()) ? fn : line;
                                    final boolean have=new File(DOWNLOAD_DIR,sanitize(dispName)).exists();
                                    final String ffn=dispName; final String fline=line;
                                    SwingUtilities.invokeLater(new Runnable(){public void run(){
                                        searchResultData.add(new String[]{ffn,fline,fline,"","http"});
                                        searchModel.addRow(new Object[]{"  "+ffn,"  \uD83C\uDF10 "+fline,have?"Already have":"HTTP"});
                                    }});
                                }
                            } else {
                                // p2p sub-entry
                                String[]hp=entryToP2P(line); if(hp==null)continue;
                                searchFilesOnPeer(hp[0],Integer.parseInt(hp[1]),entry,q);
                            }
                        }
                    }catch(Exception e){log("Peer-list search error ["+entry+"]: "+e.getMessage(),C_MUTED);}
                    continue;
                }
                // -- P2P peer ----------------------------------------------
                String[]hp=entryToP2P(entry); if(hp==null)continue;
                searchFilesOnPeer(hp[0],Integer.parseInt(hp[1]),entry,q);
            }
            SwingUtilities.invokeLater(new Runnable(){public void run(){
                searchBtn.setEnabled(true); searchProgress.setVisible(false);
                int rows=searchModel.getRowCount();
                searchStatusLbl.setText(rows==0?"  No results for \""+q+"\".":"  "+rows+" result(s) for \""+q+"\".");
                log("Search \""+q+"\": "+rows+" result(s).",C_SRCH);
            }});
        }});
    }

    private void searchFilesOnPeer(final String host, final int rp, final String srcLabel, final String q){
        for(final String fn : listRemoteFiles(host, rp)){
            if(fn.toLowerCase().contains(q)){
                final boolean have=new File(DOWNLOAD_DIR,fn).exists();
                SwingUtilities.invokeLater(new Runnable(){public void run(){
                    searchResultData.add(new String[]{fn,srcLabel,host,String.valueOf(rp),"p2p"});
                    searchModel.addRow(new Object[]{"  "+fn,"  "+srcLabel,have?"Already have":""});
                }});
            }
        }
    }

    private void clearSearch(){searchModel.setRowCount(0);searchResultData.clear();searchField.setText("");searchStatusLbl.setText("  Type a keyword and press Search.");}

    private void downloadSelected(){
        int[]rows=searchTable.getSelectedRows(); if(rows.length==0){log("Select a row first.",C_WARN);return;}
        for(int row:rows){if(row<searchResultData.size()){final String[]d=searchResultData.get(row);final int r=row;pool.submit(new Runnable(){public void run(){downloadSearchResult(r,d);}});}}
    }
    private void downloadAllResults(){
        if(searchResultData.isEmpty()){log("No results.",C_WARN);return;}
        for(int i=0;i<searchResultData.size();i++){
            String st=(String)searchModel.getValueAt(i,2);
            if(!"Already have".equals(st==null?"":st.trim())){final String[]d=searchResultData.get(i);final int row=i;pool.submit(new Runnable(){public void run(){downloadSearchResult(row,d);}});}}
    }

    private void downloadSearchResult(final int row, String[]data){
        // data = [filename, displaySrc, host/url, portOrEmpty, type]
        final String fname=data[0]; final String type=data.length>=5?data[4]:"p2p";
        String st=(String)searchModel.getValueAt(row,2);
        if("Already have".equals(st)){return;}

        if("http".equals(type)){
            // Direct HTTP download — no blockchain record
            final String url=data[2];
            setSearchSt(row,"Downloading...");
            boolean ok=downloadHttpFile(url);
            setSearchSt(row,ok?"Downloaded":"Error");
            return;
        }

        // P2P download
        final String host=data[2]; final int rp;
        try{rp=Integer.parseInt(data[3]);}catch(NumberFormatException e){setSearchSt(row,"Error: bad port");return;}
        File dest=new File(DOWNLOAD_DIR,fname); if(dest.exists()){setSearchSt(row,"Already have");return;}
        setSearchSt(row,"Downloading..."); log("Downloading: "+fname+" from "+host+":"+rp,C_ACCENT);
        try{Socket s=connect(host,rp); if(s==null){setSearchSt(row,"Error: no connect");return;}
            PrintWriter out=new PrintWriter(s.getOutputStream(),true);
            BufferedReader in=new BufferedReader(new InputStreamReader(s.getInputStream()));
            out.println(CMD_GET+" "+fname); String resp=in.readLine();
            if(resp==null||!resp.startsWith(CMD_OK)){s.close();setSearchSt(row,"Error: refused");log("Refused: "+fname,C_ERR);return;}
            long len=Long.parseLong(resp.split(" ")[1]); out.flush();
            receiveFile(s.getInputStream(),dest,len); s.close();
            setSearchSt(row,"Downloaded"); log("Downloaded: "+fname+" ("+humanSize(len)+")",C_OK);
            final File df=dest; final String rh=host; final int rport=rp;
            pool.submit(new Runnable(){public void run(){String sp=fetchRemotePubKey(rh,rport);createAndPublishBlock(df,sp,"");refreshFiles();}});
            notifyInfoEndpoints(dest, host);
        }catch(Exception e){new File(DOWNLOAD_DIR,fname).delete();setSearchSt(row,"Error: "+e.getMessage());log("Error: "+e.getMessage(),C_ERR);}
    }

    private void setSearchSt(final int row,final String st){SwingUtilities.invokeLater(new Runnable(){public void run(){if(row<searchModel.getRowCount())searchModel.setValueAt(st,row,2);}});}

    // -------------------------------------------------------------------------
    //  UI CONSTRUCTION
    // -------------------------------------------------------------------------
    private void buildUI(){
        frame=new JFrame("Ant Meento GUI  v4.2  —  UPnP · DHT · PKI · Blockchain · P2P");
        frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame.setSize(1220,800); frame.setMinimumSize(new Dimension(1000,620));
        frame.setLocationRelativeTo(null); frame.getContentPane().setBackground(C_BG);
        frame.addWindowListener(new WindowAdapter(){public void windowClosing(WindowEvent e){doExit();}});
        frame.setLayout(new BorderLayout(0,0));
        frame.add(buildHeader(),BorderLayout.NORTH);
        frame.add(buildCenter(),BorderLayout.CENTER);
        frame.add(buildStatusBar(),BorderLayout.SOUTH);
    }

    private JPanel buildHeader(){
        JPanel h=new JPanel(new BorderLayout()); h.setBackground(C_PANEL);
        h.setBorder(new MatteBorder(0,0,1,0,C_BORDER)); h.setPreferredSize(new Dimension(0,72));
        // Left: logo + fingerprint + DHT status
        JPanel left=new JPanel(new GridLayout(3,1)); left.setOpaque(false); left.setBorder(new EmptyBorder(6,14,6,0));
        JLabel logo=new JLabel("\u25B6  ANT MEENTO GUI  v4.0"); logo.setFont(new Font("Monospaced",Font.BOLD,15)); logo.setForeground(C_ACCENT);
        fingerprintLabel=new JLabel("ID: initializing..."); fingerprintLabel.setFont(new Font("Monospaced",Font.PLAIN,10)); fingerprintLabel.setForeground(C_MUTED);
        dhtStatusLbl=new JLabel("  DHT: not started"); dhtStatusLbl.setFont(new Font("Monospaced",Font.PLAIN,10)); dhtStatusLbl.setForeground(C_CHAIN);
        left.add(logo); left.add(fingerprintLabel); left.add(dhtStatusLbl); h.add(left,BorderLayout.WEST);
        // Right: receive toggle + port
        JPanel right=new JPanel(new FlowLayout(FlowLayout.RIGHT,8,0)); right.setOpaque(false); right.setBorder(new EmptyBorder(14,0,14,8));
        receiveModeCheck=new JCheckBox("RECEIVE FILES"); receiveModeCheck.setSelected(true);
        receiveModeCheck.setFont(new Font("Monospaced",Font.BOLD,10)); receiveModeCheck.setForeground(C_ACCENT2);
        receiveModeCheck.setBackground(C_PANEL); receiveModeCheck.setOpaque(false); receiveModeCheck.setFocusPainted(false);
        receiveModeCheck.addItemListener(new ItemListener(){public void itemStateChanged(ItemEvent e){receiveMode=receiveModeCheck.isSelected();updateReceiveLbl();log("Receive mode: "+(receiveMode?"ON":"OFF"),C_WARN);}});
        receiveModeLabel=new JLabel(); receiveModeLabel.setFont(new Font("Monospaced",Font.BOLD,10)); updateReceiveLbl();
        JLabel portTxt=new JLabel("PORT:"); portTxt.setFont(new Font("Monospaced",Font.PLAIN,10)); portTxt.setForeground(C_MUTED);
        final JTextField pf=new JTextField(String.valueOf(port),6); styleTextField(pf); pf.setFont(new Font("Monospaced",Font.BOLD,12)); pf.setForeground(C_ACCENT);
        JButton pb=makeButton("APPLY",C_ACCENT); pb.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){
            try{int p=Integer.parseInt(pf.getText().trim());if(p<1||p>65535)throw new NumberFormatException();port=p;log("Port -> "+port,C_WARN);restartServer();}
            catch(NumberFormatException ex){log("Invalid port",C_ERR);}}});
        portLabel=new JLabel("\u25CF  OFFLINE"); portLabel.setFont(new Font("Monospaced",Font.BOLD,10)); portLabel.setForeground(C_ERR);
        JButton dhtBtn=makeButton("DHT REFRESH",C_CHAIN); dhtBtn.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){pool.submit(new Runnable(){public void run(){bootstrapDHT();}});}});
        right.add(receiveModeCheck); right.add(receiveModeLabel); right.add(Box.createHorizontalStrut(6));
        right.add(dhtBtn); right.add(Box.createHorizontalStrut(6));
        right.add(portTxt); right.add(pf); right.add(pb); right.add(Box.createHorizontalStrut(4)); right.add(portLabel);
        h.add(right,BorderLayout.EAST);
        SwingUtilities.invokeLater(new Runnable(){public void run(){fingerprintLabel.setText("ID: "+myFingerprint+"   ["+myPublicKeyB64.substring(0,16)+"...]");}});
        return h;
    }
    private void updateReceiveLbl(){if(receiveMode){receiveModeLabel.setText("\u25CF ON");receiveModeLabel.setForeground(C_OK);}else{receiveModeLabel.setText("\u25CF OFF");receiveModeLabel.setForeground(C_ERR);}}

    private JSplitPane buildCenter(){
        JSplitPane sp=new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,buildLeftTabs(),buildLogPanel());
        sp.setDividerLocation(780); sp.setDividerSize(4); sp.setBackground(C_BG); sp.setBorder(null); sp.setOpaque(false); return sp;
    }

    private JTabbedPane buildLeftTabs(){
        JTabbedPane t=new JTabbedPane(); t.setBackground(C_BG); t.setForeground(C_TEXT); t.setFont(new Font("Monospaced",Font.BOLD,11));
        t.addTab("  FILES  ",buildFilesTab()); t.addTab("  SEARCH ",buildSearchTab());
        t.addTab(" SERVERS ",buildServersTab()); t.addTab(" \u26D3 CHAIN  ",buildChainTab());
        return t;
    }

    @SuppressWarnings("unchecked")
    private JPanel buildFilesTab(){
        JPanel p=new JPanel(new BorderLayout()); p.setBackground(C_BG);
        JPanel bar=new JPanel(new FlowLayout(FlowLayout.LEFT,8,8)); bar.setBackground(C_PANEL); bar.setBorder(new MatteBorder(0,0,1,0,C_BORDER));
        syncBtn=makeButton("  \u21BB  SYNC ALL",C_ACCENT2); syncBtn.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){pool.submit(new Runnable(){public void run(){syncAll();}});}});
        JButton rfr=makeButton("  \u21BA  REFRESH",C_ACCENT); rfr.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){refreshFiles();}});
        JButton opn=makeButton("  \u25A1  OPEN FOLDER",C_MUTED); opn.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){try{Desktop.getDesktop().open(new File(DOWNLOAD_DIR));}catch(Exception ex){log("Open failed: "+ex.getMessage(),C_ERR);}}});
        syncProgress=new JProgressBar(); syncProgress.setBackground(C_CARD); syncProgress.setForeground(C_ACCENT2); syncProgress.setPreferredSize(new Dimension(120,16)); syncProgress.setBorder(new LineBorder(C_BORDER)); syncProgress.setVisible(false);
        bar.add(syncBtn); bar.add(rfr); bar.add(opn); bar.add(syncProgress); p.add(bar,BorderLayout.NORTH);
        filesModel=new DefaultTableModel(new String[]{"  Filename","  Size","  Modified"},0){public boolean isCellEditable(int r,int c){return false;}};
        filesTable=buildTable(filesModel); filesTable.getColumnModel().getColumn(0).setPreferredWidth(300); filesTable.getColumnModel().getColumn(1).setPreferredWidth(90); filesTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        p.add(darkScroll(filesTable),BorderLayout.CENTER);
        JLabel dh=new JLabel("  \u2193  Drop files here to share"); dh.setFont(new Font("Monospaced",Font.PLAIN,11)); dh.setForeground(C_MUTED); dh.setBackground(C_PANEL); dh.setOpaque(true); dh.setBorder(new MatteBorder(1,0,0,0,C_BORDER)); dh.setPreferredSize(new Dimension(0,26)); p.add(dh,BorderLayout.SOUTH);
        new DropTarget(p,new DropTargetAdapter(){public void drop(DropTargetDropEvent ev){
            try{ev.acceptDrop(DnDConstants.ACTION_COPY);List<File> dr=(List<File>)ev.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
            for(File f:dr){if(!f.isFile())continue;File dt=new File(DOWNLOAD_DIR,f.getName());if(dt.exists()){log("Exists: "+f.getName(),C_WARN);continue;}copyFile(f,dt);log("Added: "+f.getName(),C_OK);}refreshFiles();}catch(Exception ex){log("Drop error: "+ex.getMessage(),C_ERR);}}});
        return p;
    }

    private JPanel buildSearchTab(){
        JPanel p=new JPanel(new BorderLayout(0,0)); p.setBackground(C_BG);
        JPanel sb=new JPanel(new BorderLayout(6,0)); sb.setBackground(C_PANEL); sb.setBorder(new CompoundBorder(new MatteBorder(0,0,1,0,C_BORDER),new EmptyBorder(10,10,10,10)));
        JLabel sl=new JLabel("SEARCH:"); sl.setFont(new Font("Monospaced",Font.BOLD,11)); sl.setForeground(C_MUTED); sl.setBorder(new EmptyBorder(0,0,0,6));
        searchField=new JTextField(); styleTextField(searchField); searchField.setFont(new Font("Monospaced",Font.PLAIN,13)); searchField.setForeground(C_SRCH); searchField.setCaretColor(C_SRCH);
        searchField.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){doSearch();}});
        searchBtn=makeButton("  \u2315  SEARCH",C_SRCH); searchBtn.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){doSearch();}});
        JPanel lp=new JPanel(new BorderLayout(6,0)); lp.setOpaque(false); lp.add(sl,BorderLayout.WEST); lp.add(searchField,BorderLayout.CENTER);
        sb.add(lp,BorderLayout.CENTER); sb.add(searchBtn,BorderLayout.EAST); p.add(sb,BorderLayout.NORTH);
        searchModel=new DefaultTableModel(new String[]{"  Filename","  Source","  Status"},0){public boolean isCellEditable(int r,int c){return false;}};
        searchTable=buildTable(searchModel);
        searchTable.getColumnModel().getColumn(0).setPreferredWidth(220); searchTable.getColumnModel().getColumn(1).setPreferredWidth(260); searchTable.getColumnModel().getColumn(2).setPreferredWidth(110);
        // Colour Source column: orange for HTTP entries
        searchTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer(){
            public Component getTableCellRendererComponent(JTable t,Object v,boolean sl,boolean fc,int row,int col){
                super.getTableCellRendererComponent(t,v,sl,fc,row,col);
                String val=v==null?"":v.toString();
                if(sl){setBackground(new Color(0x00,0x70,0xA0));setForeground(Color.WHITE);}
                else{setBackground(row%2==0?C_CARD:C_ROWALT);setForeground(val.contains("\uD83C\uDF10")?C_HTTP:C_MUTED);}
                setFont(new Font("Monospaced",Font.PLAIN,10));return this;}});
        searchTable.getColumnModel().getColumn(2).setCellRenderer(statusRenderer()); p.add(darkScroll(searchTable),BorderLayout.CENTER);
        JPanel ab=new JPanel(new BorderLayout()); ab.setBackground(C_PANEL); ab.setBorder(new MatteBorder(1,0,0,0,C_BORDER));
        JPanel la=new JPanel(new FlowLayout(FlowLayout.LEFT,8,6)); la.setOpaque(false);
        JButton ds=makeButton("  \u2193  DOWNLOAD SELECTED",C_ACCENT2); ds.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){downloadSelected();}});
        JButton da=makeButton("  \u21D3  DOWNLOAD ALL",C_ACCENT); da.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){downloadAllResults();}});
        JButton cl=makeButton("  \u2715  CLEAR",C_MUTED); cl.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){clearSearch();}});
        la.add(ds); la.add(da); la.add(cl);
        searchStatusLbl=new JLabel("  Search across P2P peers, DHT entries, and HTTP file URLs.");
        searchStatusLbl.setFont(new Font("Monospaced",Font.PLAIN,11)); searchStatusLbl.setForeground(C_MUTED);
        searchProgress=new JProgressBar(); searchProgress.setIndeterminate(true); searchProgress.setBackground(C_CARD); searchProgress.setForeground(C_SRCH); searchProgress.setPreferredSize(new Dimension(100,14)); searchProgress.setBorder(new LineBorder(C_BORDER)); searchProgress.setVisible(false);
        JPanel rp=new JPanel(new FlowLayout(FlowLayout.RIGHT,8,8)); rp.setOpaque(false); rp.add(searchProgress); rp.add(searchStatusLbl);
        ab.add(la,BorderLayout.WEST); ab.add(rp,BorderLayout.EAST); p.add(ab,BorderLayout.SOUTH);
        return p;
    }

    private JPanel buildServersTab(){
        JPanel p=new JPanel(new BorderLayout()); p.setBackground(C_BG);
        JPanel bar=new JPanel(new FlowLayout(FlowLayout.LEFT,8,8)); bar.setBackground(C_PANEL); bar.setBorder(new MatteBorder(0,0,1,0,C_BORDER));
        JButton add=makeButton("  +  ADD",C_ACCENT2); add.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){showAddServerDialog();}});
        JButton rem=makeButton("  \u2212  REMOVE",C_ERR); rem.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){removeSelectedServer();}});
        JButton rfr=makeButton("  \u21BA  REFRESH",C_ACCENT); rfr.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){refreshServers();}});
        JButton dht=makeButton("  \u21CB  REFRESH DHT",C_CHAIN); dht.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){pool.submit(new Runnable(){public void run(){bootstrapDHT();}});}});
        bar.add(add); bar.add(rem); bar.add(rfr); bar.add(dht); p.add(bar,BorderLayout.NORTH);
        serversModel=new DefaultTableModel(new String[]{"  Entry (server / HTTP file / peer-list)"},0){public boolean isCellEditable(int r,int c){return false;}};
        serversTable=buildTable(serversModel);
        // Colour-code entries: orange for HTTP, cyan for p2p
        serversTable.getColumnModel().getColumn(0).setCellRenderer(new DefaultTableCellRenderer(){
            public Component getTableCellRendererComponent(JTable t,Object v,boolean sl,boolean fc,int row,int col){
                super.getTableCellRendererComponent(t,v,sl,fc,row,col);
                String val=v==null?"":v.toString().trim();
                if(sl){setBackground(new Color(0x00,0x70,0xA0));setForeground(Color.WHITE);}
                else{setBackground(row%2==0?C_CARD:C_ROWALT);
                    if(isHttpFileUrl(val))setForeground(C_HTTP);
                    else if(val.startsWith("http"))setForeground(C_CHAIN);
                    else setForeground(C_TEXT);}
                setFont(new Font("Monospaced",Font.PLAIN,12));return this;}});
        p.add(darkScroll(serversTable),BorderLayout.CENTER);
        // Legend
        JPanel legend=new JPanel(new FlowLayout(FlowLayout.LEFT,14,4)); legend.setBackground(C_PANEL); legend.setBorder(new MatteBorder(1,0,0,0,C_BORDER));
        addLegend(legend,"  P2P peer",C_TEXT); addLegend(legend,"  DHT peer-list URL",C_CHAIN); addLegend(legend,"  HTTP file URLs hidden (searchable via SEARCH tab)",C_MUTED);
        p.add(legend,BorderLayout.SOUTH);
        return p;
    }

    private void addLegend(JPanel panel, String text, Color color){
        JLabel l=new JLabel(text); l.setFont(new Font("Monospaced",Font.PLAIN,10)); l.setForeground(color); panel.add(l);
    }

    private JPanel buildChainTab(){
        JPanel p=new JPanel(new BorderLayout(0,0)); p.setBackground(C_BG);
        JPanel bar=new JPanel(new FlowLayout(FlowLayout.LEFT,8,8)); bar.setBackground(C_PANEL); bar.setBorder(new MatteBorder(0,0,1,0,C_BORDER));
        JButton sc=makeButton("  \u21BB  SYNC CHAIN",C_CHAIN); sc.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){pool.submit(new Runnable(){public void run(){syncChainFromPeers();}});}});
        JButton vf=makeButton("  \u2714  VERIFY",C_ACCENT2); vf.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){verifyFullChain();}});
        JButton rf=makeButton("  \u21BA  REFRESH",C_ACCENT); rf.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){refreshChainTable();}});
        JButton op=makeButton("  \u25A1  OPEN",C_MUTED); op.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){try{Desktop.getDesktop().open(new File(BLOCKCHAIN_DIR));}catch(Exception ex){log("Open failed",C_ERR);}}});
        bar.add(sc); bar.add(vf); bar.add(rf); bar.add(op); p.add(bar,BorderLayout.NORTH);
        chainModel=new DefaultTableModel(new String[]{"  #","  Filename","  Size","  SHA-256","  Sender","  Time","  Hash"},0){public boolean isCellEditable(int r,int c){return false;}};
        chainTable=buildTable(chainModel);
        chainTable.getColumnModel().getColumn(0).setPreferredWidth(40); chainTable.getColumnModel().getColumn(1).setPreferredWidth(180);
        chainTable.getColumnModel().getColumn(2).setPreferredWidth(80); chainTable.getColumnModel().getColumn(3).setPreferredWidth(110);
        chainTable.getColumnModel().getColumn(4).setPreferredWidth(100); chainTable.getColumnModel().getColumn(5).setPreferredWidth(130);
        chainTable.getColumnModel().getColumn(6).setPreferredWidth(120);
        chainTable.getColumnModel().getColumn(6).setCellRenderer(new DefaultTableCellRenderer(){
            public Component getTableCellRendererComponent(JTable t,Object v,boolean sl,boolean fc,int row,int col){
                super.getTableCellRendererComponent(t,v,sl,fc,row,col);
                if(!sl){setBackground(row%2==0?C_CARD:C_ROWALT);setForeground(C_CHAIN);}
                else{setBackground(new Color(0x00,0x70,0xA0));setForeground(Color.WHITE);}
                setFont(new Font("Monospaced",Font.PLAIN,11));return this;}});
        p.add(darkScroll(chainTable),BorderLayout.CENTER);
        chainStatusLbl=new JLabel("  Blockchain ledger — one block per P2P transfer (HTTP downloads are not recorded)."); chainStatusLbl.setFont(new Font("Monospaced",Font.PLAIN,11)); chainStatusLbl.setForeground(C_MUTED); chainStatusLbl.setBackground(C_PANEL); chainStatusLbl.setOpaque(true); chainStatusLbl.setBorder(new MatteBorder(1,0,0,0,C_BORDER)); chainStatusLbl.setPreferredSize(new Dimension(0,26)); p.add(chainStatusLbl,BorderLayout.SOUTH);
        return p;
    }

    private JPanel buildLogPanel(){
        JPanel p=new JPanel(new BorderLayout()); p.setBackground(C_BG); p.setMinimumSize(new Dimension(200,0));
        JLabel t=new JLabel("  ACTIVITY LOG"); t.setFont(new Font("Monospaced",Font.BOLD,11)); t.setForeground(C_MUTED); t.setBackground(C_PANEL); t.setOpaque(true); t.setBorder(new MatteBorder(0,0,1,0,C_BORDER)); t.setPreferredSize(new Dimension(0,30)); p.add(t,BorderLayout.NORTH);
        logPane=new JTextPane(); logPane.setEditable(false); logPane.setBackground(C_BG); logPane.setFont(new Font("Monospaced",Font.PLAIN,11)); p.add(darkScroll(logPane),BorderLayout.CENTER);
        JPanel bot=new JPanel(new FlowLayout(FlowLayout.RIGHT,8,4)); bot.setBackground(C_PANEL); bot.setBorder(new MatteBorder(1,0,0,0,C_BORDER));
        JButton cl=makeButton("CLEAR LOG",C_MUTED); cl.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){logPane.setText("");}});
        bot.add(cl); p.add(bot,BorderLayout.SOUTH); return p;
    }

    private JPanel buildStatusBar(){
        JPanel bar=new JPanel(new BorderLayout()); bar.setBackground(C_PANEL); bar.setBorder(new MatteBorder(1,0,0,0,C_BORDER)); bar.setPreferredSize(new Dimension(0,24));
        statusLabel=new JLabel("  Initializing..."); statusLabel.setFont(new Font("Monospaced",Font.PLAIN,11)); statusLabel.setForeground(C_MUTED);
        JLabel cp=new JLabel("Ant Meento GUI v4.0   "); cp.setFont(new Font("Monospaced",Font.PLAIN,10)); cp.setForeground(new Color(0x2A,0x3A,0x4E));
        bar.add(statusLabel,BorderLayout.WEST); bar.add(cp,BorderLayout.EAST); return bar;
    }

    private void refreshChainTable(){
        final List<Block> snap; synchronized(chainLock){snap=new ArrayList<Block>(chain);}
        final SimpleDateFormat sdf=new SimpleDateFormat("dd/MM/yy HH:mm");
        SwingUtilities.invokeLater(new Runnable(){public void run(){
            chainModel.setRowCount(0);
            for(int i=0;i<snap.size();i++){Block b=snap.get(i);
                String sid=b.senderPubKey.length()>=8?b.senderPubKey.substring(0,8)+"...":b.senderPubKey;
                chainModel.addRow(new Object[]{"  "+(i+1),"  "+b.filename,"  "+humanSize(b.filesize),
                    "  "+b.sha256.substring(0,Math.min(12,b.sha256.length()))+"...","  "+sid,
                    "  "+sdf.format(new Date(b.timestamp)),"  "+b.hash.substring(0,Math.min(14,b.hash.length()))+"..."});}
            chainStatusLbl.setText("  "+snap.size()+" block(s) — P2P transfers only (HTTP downloads not recorded)  |  blockchain/");
        }});
    }

    // -------------------------------------------------------------------------
    //  UI HELPERS
    // -------------------------------------------------------------------------
    private JButton makeButton(String text, final Color fg){
        JButton b=new JButton(text){protected void paintComponent(Graphics g){Graphics2D g2=(Graphics2D)g.create();g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);g2.setColor(getModel().isArmed()||getModel().isRollover()?new Color(0x25,0x35,0x48):C_CARD);g2.fillRoundRect(0,0,getWidth(),getHeight(),6,6);g2.setColor(fg.darker());g2.drawRoundRect(0,0,getWidth()-1,getHeight()-1,6,6);g2.dispose();super.paintComponent(g);}};
        b.setForeground(fg);b.setFont(new Font("Monospaced",Font.BOLD,11));b.setFocusPainted(false);b.setBorderPainted(false);b.setContentAreaFilled(false);b.setOpaque(false);b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));b.setMargin(new Insets(4,10,4,10));return b;
    }
    private void styleTextField(JTextField f){f.setBackground(C_CARD);f.setForeground(C_TEXT);f.setCaretColor(C_ACCENT);f.setBorder(new CompoundBorder(new LineBorder(C_BORDER,1),new EmptyBorder(2,6,2,6)));f.setFont(new Font("Monospaced",Font.PLAIN,12));}
    private JTable buildTable(DefaultTableModel m){
        JTable t=new JTable(m){public Component prepareRenderer(TableCellRenderer r,int row,int col){Component c=super.prepareRenderer(r,row,col);if(isRowSelected(row)){c.setBackground(new Color(0x00,0x70,0xA0));c.setForeground(Color.WHITE);}else{c.setBackground(row%2==0?C_CARD:C_ROWALT);c.setForeground(C_TEXT);}return c;}};
        t.setBackground(C_CARD);t.setForeground(C_TEXT);t.setFont(new Font("Monospaced",Font.PLAIN,12));t.setRowHeight(26);t.setGridColor(C_BORDER);t.setShowGrid(false);t.setIntercellSpacing(new Dimension(0,1));t.setSelectionBackground(new Color(0x00,0x60,0x90));t.setSelectionForeground(Color.WHITE);t.setFillsViewportHeight(true);
        JTableHeader h=t.getTableHeader();h.setBackground(C_PANEL);h.setForeground(C_MUTED);h.setFont(new Font("Monospaced",Font.BOLD,11));h.setBorder(new MatteBorder(0,0,1,0,C_BORDER));h.setReorderingAllowed(false);return t;
    }
    private DefaultTableCellRenderer statusRenderer(){return new DefaultTableCellRenderer(){public Component getTableCellRendererComponent(JTable t,Object v,boolean sl,boolean fc,int row,int col){super.getTableCellRendererComponent(t,v,sl,fc,row,col);String val=v==null?"":v.toString().trim();if(sl){setBackground(new Color(0x00,0x70,0xA0));setForeground(Color.WHITE);}else{setBackground(row%2==0?C_CARD:C_ROWALT);if("Downloaded".equals(val))setForeground(C_OK);else if("Downloading...".equals(val))setForeground(C_WARN);else if("Already have".equals(val))setForeground(C_MUTED);else if("HTTP".equals(val))setForeground(C_HTTP);else if(val.startsWith("Error"))setForeground(C_ERR);else setForeground(C_TEXT);}setFont(new Font("Monospaced",Font.BOLD,11));return this;}};}
    private JScrollPane darkScroll(Component c){JScrollPane sp=new JScrollPane(c);sp.setBorder(null);sp.setBackground(C_BG);sp.getViewport().setBackground(C_BG);sp.getVerticalScrollBar().setBackground(C_PANEL);sp.getHorizontalScrollBar().setBackground(C_PANEL);return sp;}

    private void showAddServerDialog(){
        final JDialog d=new JDialog(frame,"Add Entries",true);d.setSize(520,320);d.setLocationRelativeTo(frame);d.getContentPane().setBackground(C_PANEL);d.setLayout(new BorderLayout(10,10));
        JPanel topPanel=new JPanel(new BorderLayout()); topPanel.setOpaque(false);
        JLabel l=new JLabel("  Enter entries (one per line):"); l.setFont(new Font("Monospaced",Font.BOLD,12)); l.setForeground(C_ACCENT); l.setBorder(new EmptyBorder(10,0,2,0)); topPanel.add(l,BorderLayout.NORTH);
        JLabel hint=new JLabel("  • host.com:52525  (P2P peer)   • https://host:52525/path  (P2P via URL)   • https://host/file.jpg  (HTTP file)   • https://host/list.txt  (peer list)   — plain text / HTML rejected");
        hint.setFont(new Font("Monospaced",Font.PLAIN,9)); hint.setForeground(C_WARN); topPanel.add(hint,BorderLayout.SOUTH);
        d.add(topPanel,BorderLayout.NORTH);
        final JTextArea a=new JTextArea();a.setBackground(C_CARD);a.setForeground(C_TEXT);a.setCaretColor(C_ACCENT);a.setFont(new Font("Monospaced",Font.PLAIN,12));a.setBorder(new EmptyBorder(6,8,6,8));
        JScrollPane sp=darkScroll(a);sp.setBorder(new LineBorder(C_BORDER));d.add(sp,BorderLayout.CENTER);
        JPanel bt=new JPanel(new FlowLayout(FlowLayout.RIGHT,10,10));bt.setBackground(C_PANEL);
        JButton cn=makeButton("CANCEL",C_MUTED);cn.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){d.dispose();}});
        JButton sv=makeButton("SAVE",C_ACCENT2);sv.addActionListener(new ActionListener(){public void actionPerformed(ActionEvent e){
            String[]lines=a.getText().split("\n");Set<String> ex=loadServers();int added=0;
            List<String> rejected=new ArrayList<String>();
            for(String line:lines){
                line=line.trim(); if(line.isEmpty()) continue;
                if(!isValidEntry(line)){ rejected.add(line); continue; }
                if(ex.add(line)){added++;dhtEntries.add(line);}
            }
            saveServers(ex);
            if(!rejected.isEmpty()){
                log("Rejected "+rejected.size()+" invalid entr(y/ies): "+rejected,C_ERR);
                JOptionPane.showMessageDialog(d,
                    "The following entries were rejected (invalid format):\n\n"
                    +String.join("\n",rejected)
                    +"\n\nAccepted formats:\n"
                    +"  host.com:52525\n  192.168.1.5:52525\n"
                    +"  https://example.com/servers.txt\n  https://host:52525/path\n  https://site.com/file.jpg",
                    "Invalid Entries",JOptionPane.WARNING_MESSAGE);
            }
            log("Added "+added+" entr(y/ies). Total: "+ex.size(),C_OK);
            refreshServers(); d.dispose();}});
        bt.add(cn);bt.add(sv);d.add(bt,BorderLayout.SOUTH);d.setVisible(true);
    }
    private void removeSelectedServer(){
        int row=serversTable.getSelectedRow(); if(row<0){log("Select an entry first.",C_WARN);return;}
        String url=((String)serversModel.getValueAt(row,0)).trim(); Set<String> s=loadServers(); s.remove(url); saveServers(s); dhtEntries.remove(url);
        log("Removed: "+url,C_WARN); refreshServers();
    }
    private void refreshFiles(){
        final List<String> ns=localFileNames(); final SimpleDateFormat sdf=new SimpleDateFormat("yyyy-MM-dd HH:mm");
        SwingUtilities.invokeLater(new Runnable(){public void run(){filesModel.setRowCount(0);for(String n:ns){File f=new File(DOWNLOAD_DIR,n);filesModel.addRow(new Object[]{"  "+n,"  "+humanSize(f.length()),"  "+sdf.format(new Date(f.lastModified()))});}
        setStatus("Files: "+ns.size()+"  |  Chain: "+chain.size()+" blocks  |  DHT: "+dhtEntries.size()+" entries  |  Port "+port);}});
    }
    private void refreshServers(){
        // Show local servers AND dht runtime entries, but EXCLUDE pure HTTP file URLs
        // (those are used for sync/search but should not clutter the peers list)
        final Set<String> all=new LinkedHashSet<String>(loadServers());
        all.addAll(dhtEntries);
        SwingUtilities.invokeLater(new Runnable(){public void run(){
            serversModel.setRowCount(0);
            for(String s:all){
                // Hide direct HTTP file entries — they are not peers
                if(isHttpFileUrl(s) && !isHttpWithP2PPort(s)) continue;
                serversModel.addRow(new Object[]{"  "+s});
            }
        }});
    }
    private void log(final String msg, final Color color){SwingUtilities.invokeLater(new Runnable(){public void run(){try{javax.swing.text.StyledDocument doc=logPane.getStyledDocument();javax.swing.text.Style st=logPane.addStyle("s",null);javax.swing.text.StyleConstants.setForeground(st,C_MUTED);javax.swing.text.StyleConstants.setFontFamily(st,"Monospaced");javax.swing.text.StyleConstants.setFontSize(st,10);String ts=new SimpleDateFormat("HH:mm:ss").format(new Date());doc.insertString(doc.getLength(),"["+ts+"] ",st);javax.swing.text.StyleConstants.setForeground(st,color);javax.swing.text.StyleConstants.setFontSize(st,11);doc.insertString(doc.getLength(),msg+"\n",st);logPane.setCaretPosition(doc.getLength());}catch(Exception ig){}}});}
    private void setStatus(final String msg){SwingUtilities.invokeLater(new Runnable(){public void run(){statusLabel.setText("  "+msg);}});}
    private void setSyncRunning(final boolean r){SwingUtilities.invokeLater(new Runnable(){public void run(){syncBtn.setEnabled(!r);syncProgress.setVisible(r);syncProgress.setIndeterminate(r);}});}
    private void doExit(){int r=JOptionPane.showConfirmDialog(frame,"Shut down Ant Meento GUI?","Exit",JOptionPane.YES_NO_OPTION,JOptionPane.QUESTION_MESSAGE);if(r==JOptionPane.YES_OPTION){pool.shutdownNow();try{if(serverSock!=null)serverSock.close();}catch(IOException ig){}System.exit(0);}}

    // -------------------------------------------------------------------------
    //  UPNP / NAT-PMP — pure Java, no external libraries
    //
    //  Flow:
    //   1. Send UDP SSDP M-SEARCH multicast to 239.255.255.250:1900
    //      looking for urn:schemas-upnp-org:device:InternetGatewayDevice:1
    //   2. Parse the LOCATION header from the first valid reply
    //   3. HTTP GET the device description XML at that location
    //   4. Extract the <controlURL> of the WANIPConnection or WANPPPConnection service
    //   5. HTTP POST a SOAP AddPortMapping action to the control URL
    //   6. HTTP POST GetExternalIPAddress to retrieve and log the external IP
    //
    //  On success:  upnpMapped=true, upnpExternalIp set, port badge turns green+IP
    //  On failure:  logs reason at MUTED level, silently ignored (user still works via manual forwarding)
    // -------------------------------------------------------------------------

    private void doUPnP(){
        log("UPnP: discovering gateway...", C_MUTED);
        try{
            String location = ssdpDiscover(3000);
            if(location == null){ log("UPnP: no IGD found on local network.", C_MUTED); return; }
            log("UPnP: IGD found at "+location, C_MUTED);

            String controlUrl = fetchIgdControlUrl(location);
            if(controlUrl == null){ log("UPnP: could not parse IGD control URL.", C_MUTED); return; }

            // Store for later use (e.g. lease renewal)
            upnpIgdUrl = controlUrl;

            // Determine local (LAN) IP to use in the mapping
            String localIp = getLocalIp();
            if(localIp == null){ log("UPnP: could not determine local IP.", C_MUTED); return; }

            // Add the port mapping
            boolean mapped = upnpAddPortMapping(controlUrl, localIp, port);
            if(!mapped){ log("UPnP: AddPortMapping failed.", C_WARN); return; }
            upnpMapped = true;
            log("UPnP: port "+port+" mapped successfully ("+localIp+" ? WAN:"+port+")", C_OK);

            // Get external IP
            String extIp = upnpGetExternalIp(controlUrl);
            if(extIp != null){
                upnpExternalIp = extIp;
                log("UPnP: external IP = "+extIp, C_OK);
                // Update port badge to show external IP
                SwingUtilities.invokeLater(new Runnable(){public void run(){
                    portLabel.setText("\u25CF  :"+port+"  ["+extIp+"]");
                    portLabel.setForeground(C_OK);
                }});
                setStatus("Port "+port+"  |  External: "+extIp+"  |  ID: "+myFingerprint);
            }
        }catch(Exception e){
            log("UPnP: error — "+e.getMessage(), C_MUTED);
        }
    }

    /**
     * Send SSDP M-SEARCH UDP multicast and return the LOCATION URL of the first
     * InternetGatewayDevice that replies, or null if none reply within timeoutMs.
     */
    private String ssdpDiscover(int timeoutMs) throws Exception{
        String SSDP_ADDR = "239.255.255.250";
        int    SSDP_PORT = 1900;

        String msg =
            "M-SEARCH * HTTP/1.1\r\n"
            +"HOST: 239.255.255.250:1900\r\n"
            +"MAN: \"ssdp:discover\"\r\n"
            +"MX: 2\r\n"
            +"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            +"\r\n";

        byte[] bytes = msg.getBytes(StandardCharsets.UTF_8);
        DatagramSocket udp = new DatagramSocket();
        udp.setSoTimeout(timeoutMs);
        InetAddress group = InetAddress.getByName(SSDP_ADDR);

        // Send twice for reliability
        DatagramPacket send = new DatagramPacket(bytes, bytes.length, group, SSDP_PORT);
        udp.send(send);
        udp.send(send);

        byte[] buf = new byte[2048];
        long deadline = System.currentTimeMillis() + timeoutMs;
        while(System.currentTimeMillis() < deadline){
            try{
                DatagramPacket recv = new DatagramPacket(buf, buf.length);
                udp.receive(recv);
                String response = new String(recv.getData(), 0, recv.getLength(), StandardCharsets.UTF_8);
                // Look for LOCATION header (case-insensitive)
                for(String line : response.split("\r\n")){
                    if(line.toLowerCase().startsWith("location:")){
                        String loc = line.substring(9).trim();
                        udp.close();
                        return loc;
                    }
                }
            }catch(java.net.SocketTimeoutException ste){ break; }
        }
        udp.close();
        return null;
    }

    /**
     * HTTP GET the IGD device description XML and extract the controlURL of the
     * WANIPConnection or WANPPPConnection service.
     */
    private String fetchIgdControlUrl(String location) throws Exception{
        URL url = new URL(location);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(4000); conn.setReadTimeout(6000);
        conn.setRequestMethod("GET");
        if(conn.getResponseCode() < 200 || conn.getResponseCode() >= 300){
            conn.disconnect(); return null;
        }
        StringBuilder sb = new StringBuilder();
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        String line;
        while((line=br.readLine())!=null) sb.append(line).append("\n");
        br.close(); conn.disconnect();
        String xml = sb.toString();

        // Find the WANIPConnection or WANPPPConnection service block
        String controlUrl = null;
        String[] serviceTypes = {
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "urn:schemas-upnp-org:service:WANPPPConnection:1"
        };
        for(String svcType : serviceTypes){
            int svcIdx = xml.indexOf(svcType);
            if(svcIdx < 0) continue;
            // Find the <controlURL> tag after the serviceType
            int ctrlIdx = xml.indexOf("<controlURL>", svcIdx);
            if(ctrlIdx < 0) continue;
            int ctrlEnd = xml.indexOf("</controlURL>", ctrlIdx);
            if(ctrlEnd < 0) continue;
            controlUrl = xml.substring(ctrlIdx + "<controlURL>".length(), ctrlEnd).trim();
            break;
        }
        if(controlUrl == null) return null;

        // Make it absolute if it's a relative path
        if(controlUrl.startsWith("/")){
            controlUrl = url.getProtocol()+"://"+url.getHost()+":"+url.getPort()+controlUrl;
        }
        return controlUrl;
    }

    /**
     * SOAP AddPortMapping action — maps WAN port ? LAN localIp:port.
     * Returns true if the router accepted the mapping (HTTP 200).
     */
    private boolean upnpAddPortMapping(String controlUrl, String localIp, int mappingPort) throws Exception{
        String soap =
            "<?xml version=\"1.0\"?>\r\n"
            +"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            +"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
            +"<s:Body>\r\n"
            +"<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\r\n"
            +"<NewRemoteHost></NewRemoteHost>\r\n"
            +"<NewExternalPort>"+mappingPort+"</NewExternalPort>\r\n"
            +"<NewProtocol>TCP</NewProtocol>\r\n"
            +"<NewInternalPort>"+mappingPort+"</NewInternalPort>\r\n"
            +"<NewInternalClient>"+localIp+"</NewInternalClient>\r\n"
            +"<NewEnabled>1</NewEnabled>\r\n"
            +"<NewPortMappingDescription>AntMeentoGUI</NewPortMappingDescription>\r\n"
            +"<NewLeaseDuration>86400</NewLeaseDuration>\r\n"
            +"</u:AddPortMapping>\r\n"
            +"</s:Body>\r\n"
            +"</s:Envelope>\r\n";

        return soapPost(controlUrl,
            "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping", soap) != null;
    }

    /**
     * SOAP GetExternalIPAddress — returns the WAN IP as a String, or null on failure.
     */
    private String upnpGetExternalIp(String controlUrl) throws Exception{
        String soap =
            "<?xml version=\"1.0\"?>\r\n"
            +"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            +"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
            +"<s:Body>\r\n"
            +"<u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
            +"</u:GetExternalIPAddress>\r\n"
            +"</s:Body>\r\n"
            +"</s:Envelope>\r\n";

        String response = soapPost(controlUrl,
            "urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress", soap);
        if(response == null) return null;
        // Parse <NewExternalIPAddress>...</NewExternalIPAddress>
        String tag = "<NewExternalIPAddress>";
        int idx = response.indexOf(tag);
        if(idx < 0) return null;
        int end = response.indexOf("<", idx + tag.length());
        if(end < 0) return null;
        return response.substring(idx + tag.length(), end).trim();
    }

    /**
     * HTTP POST a SOAP request and return the response body, or null if HTTP != 200.
     */
    private String soapPost(String controlUrl, String soapAction, String body) throws Exception{
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        URL url = new URL(controlUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000); conn.setReadTimeout(8000);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "text/xml; charset=\"utf-8\"");
        conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));
        conn.setRequestProperty("SOAPAction", "\""+soapAction+"\"");
        conn.setRequestProperty("Connection", "Close");
        conn.getOutputStream().write(bodyBytes);
        conn.getOutputStream().flush();
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        if(is == null){ conn.disconnect(); return code >= 200 && code < 300 ? "" : null; }
        StringBuilder sb = new StringBuilder();
        BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
        String line;
        while((line=br.readLine())!=null) sb.append(line).append("\n");
        br.close(); conn.disconnect();
        return (code >= 200 && code < 300) ? sb.toString() : null;
    }

    /**
     * Get the local LAN IP address (the one that routes toward the internet,
     * not loopback).  Uses a UDP connect trick — no packet is actually sent.
     */
    private String getLocalIp(){
        try{
            DatagramSocket s = new DatagramSocket();
            s.connect(InetAddress.getByName("8.8.8.8"), 80);
            String ip = s.getLocalAddress().getHostAddress();
            s.close();
            return ip;
        }catch(Exception e){ return null; }
    }

    // -------------------------------------------------------------------------
    //  UTILITIES
    // -------------------------------------------------------------------------
    private Socket connect(String host, int rp){try{Socket s=new Socket();s.connect(new InetSocketAddress(host,rp),5000);s.setSoTimeout(30000);return s;}catch(Exception e){log("Cannot connect to "+host+":"+rp+" — "+e.getMessage(),C_ERR);return null;}}
    private void receiveFile(InputStream is,File dest,long len) throws IOException{FileOutputStream fo=new FileOutputStream(dest);byte[]buf=new byte[8192];long rem=len;while(rem>0){int n=is.read(buf,0,(int)Math.min(buf.length,rem));if(n==-1)break;fo.write(buf,0,n);rem-=n;}fo.close();}
    private void copyFile(File src,File dst) throws IOException{InputStream in=new FileInputStream(src);OutputStream out=new FileOutputStream(dst);byte[]buf=new byte[8192];int n;while((n=in.read(buf))!=-1)out.write(buf,0,n);in.close();out.close();}
    private List<String> localFileNames(){File dir=new File(DOWNLOAD_DIR);File[]files=dir.listFiles(new FileFilter(){public boolean accept(File f){return f.isFile();}});if(files==null)return Collections.emptyList();List<String> ns=new ArrayList<String>();for(File f:files)ns.add(f.getName());Collections.sort(ns);return ns;}
    private Set<String> loadServers(){Set<String> set=new LinkedHashSet<String>();File f=new File(SERVERS_FILE);if(!f.exists())return set;try{BufferedReader br=new BufferedReader(new FileReader(f));String line;while((line=br.readLine())!=null){line=line.trim();if(!line.isEmpty())set.add(line);}br.close();}catch(IOException e){log("Error reading servers.txt",C_ERR);}return set;}
    private void saveServers(Set<String> s){try{PrintWriter pw=new PrintWriter(new FileWriter(SERVERS_FILE));for(String sv:s)pw.println(sv);pw.close();}catch(IOException e){log("Error saving servers.txt",C_ERR);}}
    private void ensureDirs(){new File(DOWNLOAD_DIR).mkdirs();new File(BLOCKCHAIN_DIR).mkdirs();new File(IDENTITY_DIR).mkdirs();}
    private String sanitize(String n){return new File(n).getName().replaceAll("[^a-zA-Z0-9._\\-]","_");}
    private String humanSize(long b){if(b<1024)return b+" B";if(b<1024*1024)return String.format("%.1f KB",b/1024.0);if(b<1024L*1024*1024)return String.format("%.1f MB",b/(1024.0*1024));return String.format("%.2f GB",b/(1024.0*1024*1024));}
    private String readTxt(File f) throws IOException{BufferedReader br=new BufferedReader(new FileReader(f));StringBuilder sb=new StringBuilder();String l;while((l=br.readLine())!=null)sb.append(l).append("\n");br.close();return sb.toString().trim();}
    private void writeTxt(File f,String t) throws IOException{f.getParentFile().mkdirs();PrintWriter pw=new PrintWriter(new FileWriter(f));pw.print(t);pw.close();}
}