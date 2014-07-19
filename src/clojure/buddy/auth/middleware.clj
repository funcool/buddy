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

(ns buddy.auth.middleware
  (:require [buddy.auth.protocols :as proto]
            [buddy.auth.accessrules :as accessrules]
            [buddy.auth :refer [authenticated? throw-unauthorized]]
            [ring.util.response :refer [response response?]])
  (:import (buddy.exceptions UnauthorizedAccessException)))

(defn wrap-authentication
  "Ring middleware that enables authentication
  for your ring handler."
  [handler backend]
  (fn [request]
    (let [request (assoc request :auth-backend backend)
          rsq     (proto/parse backend request)]
      (if (response? rsq) rsq
        (if (nil? rsq)
          (handler request)
          (let [rsq (proto/authenticate backend request rsq)]
            (if (response? rsq) rsq
              (handler (or rsq request)))))))))

(defn wrap-authorization
  "Ring middleware that enables authorization
  workflow for your ring handler."
  [handler & [backend]]
  (fn [request]
    (let [backend (or backend (:auth-backend request))]
      (if (nil? backend)
        (throw (IllegalAccessError. "no backend found"))
        (try
          (handler request)
          (catch UnauthorizedAccessException e
            (proto/handle-unauthorized backend request (.-metadata e))))))))

(defn wrap-access-rules
  "An other ring middleware that helps define
  access rules for ring handler.

  This is a example of access rules list that
  `wrap-access-rules` middleware expects:

      [{:pattern #\"^/foo.*$\"
        :handler user-access}
       {:pattern #\"^/bar.*$\"
        :handler {:or [user-access admin-access]}}
       {:pattern #\"^/baz.*$\"
        :handler {:and [user-access {:or [admin-access operator-access]}]}}]

  Access rules are based on regular expressions associated with
  handlers list. All rules are evaluated in order and stops on
  first match found.

  The handler function should accept the request as first
  parameter and must return true or false. Additionaly, if
  you are using authorization middleware, the handler funcion
  can raise unauthorized exception for fast return.
  "
  [handler & [{:keys [rules policy reject-handler] :or {policy :allow}}]]
  (fn [request]
    (let [reject-handler (or reject-handler (fn [request] (throw-unauthorized)))
          request        (assoc request :access-rules {:reject-handler reject-handler
                                                       :rules rules
                                                       :policy policy})]
      (if (not rules)
        (handler request)
        (if-let [match (accessrules/match-rules request rules)]
          (let [request (update-in request [:access-rules :match] match)]
            (if (accessrules/apply-rule request match)
              (handler request)
              (reject-handler request)))
          (case policy
            :allow (handler request)
            :reject (reject-handler request)))))))
