// Interop peer backed by Bouncy Castle's low-level PQC API.
//
// Bouncy Castle is an independent FIPS 203/204/205 implementation in Java with
// no shared lineage with this package's backend, so byte-level agreement
// between the two is real cross-implementation evidence.
//
// Protocol: one JSON request per line on stdin, one JSON response per line on
// stdout. Byte fields are lowercase hex. See ../run-interop.mjs.
//
//   javac -cp bcprov.jar BouncyCastlePeer.java
//   java  -cp bcprov.jar:. BouncyCastlePeer < requests.jsonl
//
// The request objects are flat string/boolean maps produced by our own
// orchestrator, so a small reader is used rather than pulling in a JSON
// library and widening the toolchain this evidence depends on.

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;

public final class BouncyCastlePeer {

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.trim().isEmpty()) continue;
            Map<String, String> req = readFlatJson(line);
            Map<String, String> out = new LinkedHashMap<>();
            if (req.get("id") != null) out.put("id", req.get("id"));
            try {
                out.put("ok", "true");
                out.putAll(handle(req));
            } catch (Throwable err) {
                out.clear();
                if (req.get("id") != null) out.put("id", req.get("id"));
                out.put("ok", "false");
                out.put("error", err.getClass().getSimpleName() + ": " + err.getMessage());
            }
            System.out.println(writeJson(out, req.get("id")));
            System.out.flush();
        }
    }

    private static Map<String, String> handle(Map<String, String> req) throws Exception {
        String op = req.get("op");
        Map<String, String> res = new LinkedHashMap<>();

        if ("identify".equals(op)) {
            res.put("name", "Bouncy Castle bcprov");
            res.put("language", "Java");
            res.put("version", org.bouncycastle.jce.provider.BouncyCastleProvider.class
                    .getPackage().getImplementationVersion());
            res.put("java", System.getProperty("java.version"));
            return res;
        }

        String alg = req.get("alg");

        if (alg.startsWith("ML-DSA")) {
            MLDSAParameters p = (MLDSAParameters) lookup(MLDSAParameters.class, mlDsaField(alg));
            if ("keyDerive".equals(op)) {
                MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(p, unhex(req.get("seed")));
                res.put("publicKey", hex(sk.getPublicKey()));
                res.put("secretKey", hex(sk.getPrivateKey()));
                return res;
            }
            if ("sign".equals(op)) {
                // Rebuild the expanded key from the same seed the orchestrator
                // used; the wire format for a seed-form key differs between
                // libraries, so the seed is the portable handle.
                MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(p, unhex(req.get("seed")));
                MLDSASigner signer = new MLDSASigner();
                signer.init(true, withContext(sk, req.get("context")));
                byte[] msg = unhex(req.get("message"));
                signer.update(msg, 0, msg.length);
                res.put("signature", hex(signer.generateSignature()));
                return res;
            }
            if ("verify".equals(op)) {
                MLDSAPublicKeyParameters pk = new MLDSAPublicKeyParameters(p, unhex(req.get("publicKey")));
                MLDSASigner signer = new MLDSASigner();
                signer.init(false, withContext(pk, req.get("context")));
                byte[] msg = unhex(req.get("message"));
                signer.update(msg, 0, msg.length);
                res.put("valid", String.valueOf(signer.verifySignature(unhex(req.get("signature")))));
                return res;
            }
        }

        if (alg.startsWith("ML-KEM")) {
            MLKEMParameters p = (MLKEMParameters) lookup(MLKEMParameters.class, mlKemField(alg));
            if ("keyDerive".equals(op)) {
                MLKEMPrivateKeyParameters sk = new MLKEMPrivateKeyParameters(p, unhex(req.get("seed")));
                res.put("publicKey", hex(sk.getPublicKey()));
                res.put("secretKey", hex(sk.getEncoded()));
                return res;
            }
            if ("encapsulate".equals(op)) {
                MLKEMPublicKeyParameters pk = new MLKEMPublicKeyParameters(p, unhex(req.get("publicKey")));
                // internalGenerateEncapsulated takes the 32-byte m explicitly,
                // so the ciphertext is reproducible instead of depending on a
                // SecureRandom draw.
                byte[] entropy = unhex(req.get("entropy"));
                byte[] m = new byte[32];
                System.arraycopy(entropy, 0, m, 0, 32);
                SecretWithEncapsulation enc = MLKEMGenerator.internalGenerateEncapsulated(pk, m);
                res.put("ciphertext", hex(enc.getEncapsulation()));
                res.put("sharedSecret", hex(enc.getSecret()));
                return res;
            }
            if ("decapsulate".equals(op)) {
                MLKEMPrivateKeyParameters sk = new MLKEMPrivateKeyParameters(p, unhex(req.get("seed")));
                MLKEMExtractor ex = new MLKEMExtractor(sk);
                res.put("sharedSecret", hex(ex.extractSecret(unhex(req.get("ciphertext")))));
                return res;
            }
        }

        if (alg.startsWith("SLH-DSA")) {
            SLHDSAParameters p = (SLHDSAParameters) lookup(SLHDSAParameters.class, slhDsaField(alg));
            if ("keyDerive".equals(op)) {
                SLHDSAPrivateKeyParameters sk = slhKeyFromSeed(p, unhex(req.get("seed")));
                res.put("publicKey", hex(sk.getPublicKey()));
                res.put("secretKey", hex(sk.getEncoded()));
                return res;
            }
            if ("sign".equals(op)) {
                SLHDSAPrivateKeyParameters sk = slhKeyFromSeed(p, unhex(req.get("seed")));
                SLHDSASigner signer = new SLHDSASigner();
                signer.init(true, withContext(sk, req.get("context")));
                res.put("signature", hex(signer.generateSignature(unhex(req.get("message")))));
                return res;
            }
            if ("verify".equals(op)) {
                SLHDSAPublicKeyParameters pk =
                        new SLHDSAPublicKeyParameters(p, unhex(req.get("publicKey")));
                SLHDSASigner signer = new SLHDSASigner();
                signer.init(false, withContext(pk, req.get("context")));
                res.put("valid", String.valueOf(
                        signer.verifySignature(unhex(req.get("message")), unhex(req.get("signature")))));
                return res;
            }
        }

        throw new IllegalArgumentException("unsupported op/alg: " + op + "/" + alg);
    }

    /**
     * Derive an SLH-DSA private key from the same seed our side uses.
     *
     * Bouncy Castle's seed-form constructor needs the derived public root as
     * well, so it cannot take a bare (SK.seed, SK.prf, PK.seed) seed. Driving
     * the key pair generator from a fixed byte source instead makes Bouncy
     * Castle compute the root itself, which keeps this an independent
     * derivation rather than a key transfer.
     */
    private static SLHDSAPrivateKeyParameters slhKeyFromSeed(SLHDSAParameters p, byte[] seed) {
        SLHDSAKeyPairGenerator gen = new SLHDSAKeyPairGenerator();
        gen.init(new SLHDSAKeyGenerationParameters(new FixedBytes(seed), p));
        return (SLHDSAPrivateKeyParameters) gen.generateKeyPair().getPrivate();
    }

    /**
     * Serves a fixed byte string in place of random draws, and fails rather than
     * wrapping or padding if more is requested than the seed holds. Silently
     * recycling bytes would let a mismatch in how much entropy the generator
     * consumes pass as agreement.
     */
    private static final class FixedBytes extends java.security.SecureRandom {
        private final byte[] source;
        private int offset;

        FixedBytes(byte[] source) {
            this.source = source;
        }

        @Override
        public void nextBytes(byte[] out) {
            if (offset + out.length > source.length) {
                throw new IllegalStateException(
                        "generator asked for " + (offset + out.length) + " seed bytes, seed holds " + source.length);
            }
            System.arraycopy(source, offset, out, 0, out.length);
            offset += out.length;
        }
    }

    private static org.bouncycastle.crypto.CipherParameters withContext(
            org.bouncycastle.crypto.CipherParameters key, String contextHex) {
        byte[] ctx = unhex(contextHex);
        return ctx.length == 0 ? key : new ParametersWithContext(key, ctx);
    }

    // "ML-DSA-65" -> "ml_dsa_65"
    private static String mlDsaField(String alg) {
        return "ml_dsa_" + alg.substring("ML-DSA-".length());
    }

    // "ML-KEM-768" -> "ml_kem_768"
    private static String mlKemField(String alg) {
        return "ml_kem_" + alg.substring("ML-KEM-".length());
    }

    // "SLH-DSA-SHA2-192s" -> "sha2_192s"
    private static String slhDsaField(String alg) {
        String tail = alg.substring("SLH-DSA-".length());
        int dash = tail.indexOf('-');
        return tail.substring(0, dash).toLowerCase() + "_" + tail.substring(dash + 1);
    }

    private static Object lookup(Class<?> holder, String fieldName) throws Exception {
        Field f = holder.getField(fieldName);
        return f.get(null);
    }

    // ------------------------------------------------------------------ codecs

    private static byte[] unhex(String s) {
        if (s == null || s.isEmpty()) return new byte[0];
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        return sb.toString();
    }

    /**
     * Reads the flat {"key":"value"} / {"key":true} objects this peer is sent.
     * Not a general JSON parser: no nesting, arrays, escapes or numbers, and it
     * throws rather than guessing if it meets any of them.
     */
    private static Map<String, String> readFlatJson(String s) {
        Map<String, String> out = new LinkedHashMap<>();
        int i = s.indexOf('{');
        if (i < 0) throw new IllegalArgumentException("not an object: " + s);
        i++;
        while (i < s.length()) {
            while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == ',')) i++;
            if (i < s.length() && s.charAt(i) == '}') break;
            if (s.charAt(i) != '"') throw new IllegalArgumentException("expected key at " + i + " in " + s);
            int keyEnd = s.indexOf('"', i + 1);
            String key = s.substring(i + 1, keyEnd);
            i = s.indexOf(':', keyEnd) + 1;
            while (i < s.length() && s.charAt(i) == ' ') i++;
            String value;
            if (s.charAt(i) == '"') {
                int valEnd = s.indexOf('"', i + 1);
                if (s.indexOf('\\', i + 1) != -1 && s.indexOf('\\', i + 1) < valEnd) {
                    throw new IllegalArgumentException("escapes are not supported");
                }
                value = s.substring(i + 1, valEnd);
                i = valEnd + 1;
            } else {
                int valEnd = i;
                while (valEnd < s.length() && ",}".indexOf(s.charAt(valEnd)) < 0) valEnd++;
                value = s.substring(i, valEnd).trim();
                i = valEnd;
            }
            out.put(key, value);
        }
        return out;
    }

    private static String writeJson(Map<String, String> map, String id) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : map.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(e.getKey()).append("\":");
            String v = e.getValue();
            boolean bare = "true".equals(v) || "false".equals(v) || e.getKey().equals("id");
            if (bare && v != null && !v.isEmpty()) sb.append(v);
            else sb.append('"').append(v == null ? "" : v.replace("\"", "'")).append('"');
        }
        return sb.append('}').toString();
    }
}
