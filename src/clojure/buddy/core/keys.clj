;; Copyright 2013 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.core.keys
  (:require [buddy.core.codecs :refer [str->bytes bytes->hex]]))

(defprotocol ISecretKey
  (key->bytes [key] "Normalize key to byte array")
  (key->str [key] "Normalize key String"))

(extend-protocol ISecretKey
  (Class/forName "[B")
  (key->bytes [it] it)
  (key->str [it] (bytes->hex it))

  String
  (key->bytes [key] (str->bytes key))
  (key->str [key] key))
