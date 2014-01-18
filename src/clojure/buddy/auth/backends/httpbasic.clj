(ns buddy.auth.backends.httpbasic
  (:require [buddy.auth.protocols :as proto]
            [buddy.crypto.core :refer [base64->str]]
            [buddy.util :refer [m-maybe]]
            [clojure.string :refer [split]]
            [ring.util.response :refer [response? header status]]))

(defn parse-httpbasic-header
  "Given a request, try extract and parse
  http basic header."
  [request]
  (m-maybe [headers-map (:headers request)
            auth-header (get headers-map "authorization")
            pattern     (re-pattern "^Basic (.+)$")
            matches     (re-find pattern auth-header)
            decoded     (base64->str (get matches 1))]
    (let [[username, password] (split decoded #":")]
      {:username username :password password})))

(defrecord HttpBasicBackend [realm authfn not-authorized-handler]
  proto/IAuthentication
  (parse [_ request]
    (parse-httpbasic-header request))
  (authenticate [_ request data]
    (let [rsq (when authfn (authfn request data))]
      (if (response? rsq) rsq
        (assoc request :identity rsq))))

  proto/IAuthorization
  (handle-unauthorized [_ request metadata]
    (let [rsp (when not-authorized-handler
                (not-authorized-handler request metadata))
          rsp (if (response? rsp) rsp
                (if (nil? rsp) {:body ""} {:body rsp}))]
      (-> rsp
          (header "WWW-Authenticate" (format "Basic realm=\"%s\"" realm))
          (status 401)))))

(defn http-basic
  "Given some options, create a new instance
  of HttpBasicBackend and return it."
  [& {:keys [realm authfn authorization-handler] :or {realm "Buddy Auth"}}]
  (->HttpBasicBackend realm authfn authorization-handler))
