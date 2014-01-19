(ns buddy.auth.backends.stateless-token
  (:require [buddy.auth.protocols :as proto]
            [buddy.crypto.core :refer [base64->str]]
            [buddy.crypto.keys :refer [make-secret-key]]
            [buddy.crypto.signing :refer [loads]]
            [buddy.util :refer [m-maybe]]
            [clojure.string :refer [split]]
            [ring.util.response :refer [response? header status]]))

(defn parse-authorization-header
  "Given a request, try extract and parse
  authorization header."
  [request]
  (m-maybe [headers-map (:headers request)
            auth-header (get headers-map "authorization")
            pattern     (re-pattern "^Bearer (.+)$")
            matches     (re-find pattern auth-header)]
    (get matches 1)))

(defrecord StatelessTokenAuthBackend [pkey not-authorized-handler maxage]
  proto/IAuthentication
  (parse [_ request]
    (parse-authorization-header request))
  (authenticate [_ request data]
    (assoc request :identity (loads data pkey {:maxage maxage})))

  proto/IAuthorization
  (handle-unauthorized [_ request metadata]
    (let [rsp (when not-authorized-handler
                (not-authorized-handler request metadata))
          rsp (if (response? rsp) rsp
                (if (nil? rsp) {:body ""} {:body rsp}))]
      (-> rsp (status 401)))))

(defn stateless-token-backend
  "Given some options, create a new instance
  of HttpBasicBackend and return it."
  [pkey & {:keys [authorization-handler maxage]}]
  (->StatelessTokenAuthBackend
    (make-secret-key pkey)
    authorization-handler
    maxage))
