(ns buddy.crypto.keys
  (:import java.security.Key))

(defn make-secret-key
  "Generates a Key instance from given raw string key."
  [^String skey]
  (let [rawkey (.getBytes skey "UTF-8")]
    (proxy [Key] []
      (getFormat [] nil)
      (getEncoded [] rawkey)
      (toString [] skey))))
