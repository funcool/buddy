(ns buddy.crypto.hashers.protocols)

(defprotocol IHasher
  (verify [_ password encoded]
    "Verify if a plain password matches a encoded hash.")
  (make-hash [_ password salt] [_ password]
    "Make a hash from password."))
