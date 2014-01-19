(ns buddy.crypto.keys
  (:require [buddy.crypto.core :refer [str->bytes]])
  (:import java.security.Key))

(defn make-secret-key
  "Generates a Key instance from given raw string key."
  [^String skey]
  (let [rawkey (str->bytes skey)]
    (proxy [Key] []
      (getFormat [] nil)
      (getEncoded [] rawkey)
      (toString [] skey))))
