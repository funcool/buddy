(ns oauthexample.core
  (:require [compojure.route :as route]
            [compojure.core :refer :all]
            [ring.util.response :refer [response redirect content-type]]
            [ring.middleware.session :refer [wrap-session]]
            [ring.middleware.params :refer [wrap-params]]
            [ring.adapter.jetty :as jetty]
            [buddy.auth :refer [authenticated? throw-notauthorized]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-access-rules wrap-authorization]]
            [clj-http.client :as client]
            [hiccup.core :refer [html]]
            [clojure.data.json :as json])
  (:gen-class))

;; Github Authentication/Authorization constants
(def github-api-url "https://api.github.com")
(def github-client-id "yourclientid")
(def github-client-secret "yourclientsecret")
(def github-redirect-url "http://localhost:9090/authorize")
(def github-authorize-url "https://github.com/login/oauth/authorize")
(def github-access-token-url "https://github.com/login/oauth/access_token")

;; Github urls for example usage.
(def github-api-user-url (str github-api-url "/user"))
(def github-api-user-repos-url (str github-api-url "/user/repos"))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Github util functions                            ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn make-github-authorizeurl
  "Function used for build authorize url."
  []
  (str github-authorize-url (format "?client_id=%s&redirect_url=%s&state=token"
                                    github-client-id github-authorize-url)))

(defn get-github-accesstoken
  "Given authorization code, request access token
to github and returns it."
  [code]
  (let [params  {:client_id github-client-id
                 :client_secret github-client-secret
                 :code code}
        rsp     (client/get github-access-token-url {:accept :json :query-params params})
        data    (json/read-str (:body rsp) :key-fn keyword)]
    (:access_token data)))

(defn get-user-repositories
  "Given access token, get current logged user
repositories list."
  [token]
  (let [response (client/get github-api-user-repos-url {:query-params {:access_token token} :accept :json})]
    (json/read-str (:body response) :key-fn keyword)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Controllers                                      ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn home-ctrl
  [request]
  (response (html [:div [:a {:href "/repos"} "My Repos"]])))

(defn repos-ctrl
  [request]
  (let [token (get-in request [:identity :token])
        repos (get-user-repositories token)]
    (-> (html [:section
               [:h1 "My repositories"]
               [:ul (for [repo repos] [:li (:name repo)])]])
        (response)
        (content-type "text/html"))))

(defn login-ctrl
  "Login Controller
This controller does nothing more than redirect user
to github authorization page."
  [request]
  (redirect (make-github-authorizeurl)))

(defn authorize-ctrl
  "Authorize Controller
This controller works as github callback endpoind, and
should receive authorization code and exchange it
by access token."
  [request]
  (let [params (:query-params request)
        code   (get params "code")
        token  (get-github-accesstoken code)]
    (-> (redirect "/repos")
        (assoc-in [:session :identity] {:token token}))))

(defn logout-ctrl
  "Logout Controller
This controller removes all data from session,
nothing more."
  [request]
  (-> (redirect "/login")
      (assoc :session {})))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Routes and Middlewares                           ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; User defined application routes
;; using compojure routing library
;; Note: no any middleware for authorization,
;; all authorization system is totally decoupled
;; from main routes.
(defroutes app
  (GET "/" [] home-ctrl)
  (GET "/repos" [] repos-ctrl)
  (GET "/login" [] login-ctrl)
  (GET "/authorize" [] authorize-ctrl)
  (GET "/logout" [] logout-ctrl))

;; User defined unauthorized handler. Is executed on each request that
;; is marked as unauthorized by any subsystem, like: access-rules system
;; user defined controller raises notauthorized exception.
;; This function receives request and exception metadata
;; and should return valid response.
(defn unauthorized-handler
  [request metadata]
  (if (authenticated? request)
    (redirect "/")
    (redirect "/login")))

(defn -main
  [& args]
  (let [;; Create session backend overwritting its
        ;; default unauthorized request handler
        backend (session-backend :unauthorized-handler unauthorized-handler)
        ;; Define default access rules.
        ;; :handler can be any function that receives
        ;; request and returns a boolean value
        rules   [{:pattern #"^/repos$"
                  :handler authenticated?}]

        ;; Create app with buddy middlewares
        app (-> app
                (wrap-params)
                (wrap-access-rules rules {:policy :allow})
                (wrap-authorization backend)
                (wrap-authentication backend)
                (wrap-session))]
    (println "Now listening on: http://127.0.0.1:9090/")
    (jetty/run-jetty app {:port 9090})))
