(ns buddy.core.crypto.chacha
  "ChaCha20 stream cipher interface."
  (:import org.bouncycastle.crypto.engines.ChaChaEngine
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.params.ParametersWithIV))

(defn- init-engine
  [^Boolean forencrypt ^bytes key ^bytes iv & [rounds]]
  (let [rounds (or rounds 20)
        engine (ChaChaEngine. rounds)
        kp     (KeyParameter. key)
        pwi    (ParametersWithIV. kp iv)]
    (.init engine forencrypt pwi)
    engine))

(defn- process-bytes
  "Encrypt/Decript implementation."
  [^ChaChaEngine engine ^bytes input]
  (let [len  (count input)
        out  (byte-array len)]
    (.processBytes engine input 0 len out 0)
    out))

(defn encrypt
  "Encrypt data using ChaCha20 stream cipher."
  [^bytes input ^bytes key ^bytes iv]
  (let [engine (init-engine true key iv)]
    (process-bytes engine input)))

(defn decrypt
  "Decrypt data using ChaCha20 stream cipher."
  [^bytes input ^bytes key ^bytes iv]
  (let [engine (init-engine false key iv)]
    (process-bytes engine input)))
