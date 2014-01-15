(ns buddy.crypto.signing
  (:require [buddy.crypto.core :refer :all]
            [buddy.core :as core]
            [taoensso.nippy :as nippy]))

(defn- make-signature
  [s secret & [{:keys [salt sep stamp]
                :or {salt "", sep ":", stamp ""}
                :as opts}]]
  (let [secretstr (.toString secret)
        signature (hmac-sha256 s secretstr {:salt salt})]
    (format "%s%s%s" signature sep stamp)))

(defn sign
  "Given a string and optionally a key,
  return a signed and prefixed string."
  ([s, opts] (sign s core/*secret-key opts))
  ([s, pkey & [{:keys [sep salt]
                :or {sep ":" salt "clj"}
                :as opts}]]
   (let [stamp     (str->base64 (str (timestamp)))
         signature (make-signature s pkey {:salt salt
                                           :sep sep
                                           :stamp stamp})]
     (format "%s%s%s" s sep signature)))

(defn unsign
  "Unsign string using a private key globally defined."
  ([s opts] (unsign s core/*secret-key opts))
  ([s pkey & [{:keys [sep salt max-age]
               :or {sep ":" salt "clj" max-age nil}}]]
   (let [[value sig stamp] (split s (re-pattern sep))]
    (when (= sig (make-signature value pkey {:salt salt :sep "" :stamp ""}))
      (if-not (nil? max-age)
        (let [old-stamp-value (Integer/parseInt (base64->str stamp))
              age             (- (timestamp) old-stamp-value)]
          (if (> age max-age) nil value))
        value)))))

(defn dumps
  "Sign a complex data strucutres using
  serialization as intermediate step."
  [data & args]
  (let [encoded (bytes->base64 (nippy/freeze data))]
    (apply sign encoded (vec args))))

(defn loads
  "Unsign data signed with dumps."
  [s & args]
  (let [unsigned (apply unsign s (vec args))]
    (nippy/thaw (base64->bytes unsigned))))
