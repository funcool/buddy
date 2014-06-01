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

(ns buddy.core.sign.util
  "Utilities functions for digital signature namespace."
  (:import clojure.lang.Keyword))

(defn concat-two-keywords
  ([^Keyword first  ^Keyword second]
     (concat-two-keywords first second "-"))
  ([^Keyword first  ^Keyword second ^String delim]
     (let [name1 (name first)
           name2 (name second)]
       (keyword (str name1 delim name2)))))
