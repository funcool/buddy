(ns buddy.cryoto.keys
  (:import javax.crypto.Key))

(def make-secret-key
  "Generates a Key instance from given raw string key."
  [^String skey]
  (let [rawkey (.getBytes skey "UTF-8")]
    (proxy [Key Object]
      (getFormat [] nil)
      (getEncoded [] rawkey)
      (toString [] skey))))
