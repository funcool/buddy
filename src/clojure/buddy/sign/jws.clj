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


;; Links to rfcs:
;; - http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19
;; - http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-25

(ns buddy.sign.jws
  "Json Web Signature implementation."
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.mac.hmac :as hmac]
            [clj-time.coerce :as c]
            [clojure.string :as str]
            [cheshire.core :as json]))

(defprotocol ITimestamp
  "Default protocol for convert any tipe to
unix timestamp with default implementation for
java.util.Date"
  (to-timestamp [obj] "Covert to timestamp"))

(extend-protocol ITimestamp
  java.util.Date
  (to-timestamp [obj]
    (c/to-epoch obj))

  org.joda.time.DateTime
  (to-timestamp [obj]
    (c/to-epoch obj)))

(defn- normalize-date-claims
  "Normalize date related claims and return transformed object."
  [data]
  (into {} (map (fn [[key val]]
                  (if (satisfies? ITimestamp val)
                    [key (to-timestamp val)]
                    [key val])) data)))

(defn- normalize-nil-claims
  "Given a raw headers, try normalize it removing any
key with null values and convert Dates to timestamps."
  [data]
  (into {} (remove (comp nil? second) data)))

(defn- make-headers
  "Make jws header as json string"
  [alg extra-headers]
  (-> (or extra-headers {})
      (merge {:alg (.toUpperCase (name alg)) :typ "JWS"})
      (json/generate-string)
      (codecs/str->bytes)
      (codecs/bytes->safebase64)))

(defn- make-claims
  "Make jws claims as json string"
  [input exp nbf iat]
  (println 222, (-> (normalize-nil-claims {:exp exp :nbf nbf :iat iat})
                    (normalize-date-claims)
                    (merge input)
                    (json/generate-string)))
  (-> (normalize-nil-claims {:exp exp :nbf nbf :iat iat})
      (normalize-date-claims)
      (merge input)
      (json/generate-string)
      (codecs/str->safebase64)))

(defn- safe-encode
  [input]
  (-> input
      (codecs/str->bytes)
      (codecs/bytes->safebase64)))

(defn- make-signature
  [pkey alg header claims]
  (let [candidate (str/join "." [header claims])]
    (-> (hmac/hmac candidate pkey :sha256)
        (codecs/bytes->safebase64))))

(defn sign
  "Sign arbitrary length string/byte array using json web signature."
  [claims pkey & [{:keys [alg exp nbf iat headers] :or {alg :hs256 headers {}}}]]
  {:pre [(map? claims)]}
  (let [headers-data (make-headers alg headers)
        claims-data  (make-claims claims exp nbf iat)
        signature    (make-signature pkey alg headers-data claims-data)]
    (str/join "." [headers-data claims-data signature])))



