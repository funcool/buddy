;; Copyright 2014 Andrey Antukh <niwi@niwi.be>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.sign.generic
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.hmac :refer [salted-hmac-sha256]]
            [buddy.core.util :refer [timestamp]]
            [clojure.string :refer [split]]
            [taoensso.nippy :as nippy]))

(defn- make-signature
  [s pkey salt]
  (salted-hmac-sha256 s pkey salt))

(defn- make-stamped-signature
  [s pkey salt sep stamp]
  (let [candidate (str s stamp)
        signature (make-signature candidate pkey salt)]
    (format "%s%s%s" signature sep stamp)))

(defn sign
  "Given a string and secret key,
  return a signed and prefixed string."
  ([s, pkey & [{:keys [sep salt]
                :or {sep ":" salt "clj"}
                :as opts}]]
   (let [stamp     (str->base64 (str (timestamp)))
         signature (make-stamped-signature s pkey salt sep stamp)]
     (format "%s%s%s" s sep signature))))

(defn unsign
  "Given a signed string and private key with string
  was preoviously signed and return unsigned value
  if the signature is valed else nil."
  ([s pkey & [{:keys [sep salt max-age]
               :or {sep ":" salt "clj" max-age nil}}]]
   (let [[value sig stamp] (split s (re-pattern sep))
         candidate (str value stamp)]
     (when (= sig (make-signature candidate pkey salt))
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
    (when-not (nil? unsigned)
      (nippy/thaw (base64->bytes unsigned)))))
