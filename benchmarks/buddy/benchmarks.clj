(ns buddy.benchmarks
  (:require [criterium.core :as c]
            [buddy.core.sign :as sign]
            [buddy.core.keys :as keys])
  (:gen-class))

(defn bench-digital-signature
  [& args]
  (let [data     (slurp "test/_files/pubkey.ecdsa.pem")
        privkey  (keys/private-key "test/_files/privkey.3des.rsa.pem" "secret")]
    (c/with-progress-reporting
      (c/bench (sign/rsassa-pss-sha256 data privkey) :verbose))))

(defn -main
  [& args]
  (bench-digital-signature))
