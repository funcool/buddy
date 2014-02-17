(ns sessionexample.core
  (:require [compojure.route :as route]
            [compojure.core :refer :all]
            [compojure.response :refer [render]]
            [clojure.java.io :as io]
            [ring.util.response :refer [response redirect content-type]]
            [ring.middleware.session :refer [wrap-session]]
            [ring.middleware.params :refer [wrap-params]]
            [ring.adapter.jetty :as jetty]
            [buddy.auth :refer [authenticated? throw-unauthorized]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.middleware :refer [wrap-authentication wrap-authorization]])
  (:gen-class))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Controllers                                      ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn home-ctrl
  [request]
  ;; This is a simple example of using a unauthorized exception
  ;; and how is captured by authorization backend and the default
  ;; unauthorized request handler redirects a user to login page.
  (if-not (authenticated? request)
    (throw-unauthorized)
    (response (slurp (io/resource "index.html")))))

(defn login-ctrl
  [request]
  (cond
   (= (:request-method request) :get)
   (render (slurp (io/resource "login.html")) request)

   (= (:request-method request) :post)
   (let [username  (get-in request [:form-params "username"])
         session   (-> (:session request)
                       (assoc :identity (keyword username)))]
     (-> (redirect (get-in request [:query-params :next] "/"))
         (assoc :session session)))))

(defn logout-ctrl
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
  (ANY "/login" [] login-ctrl)
  (GET "/logout" [] logout-ctrl))


;; Self defined unauthorized handler

(defn unauthorized-handler
  [request metadata]
  (if (authenticated? request)

    ;; If request is authenticated, raise 403 instead
    ;; of 401 (because user is authenticated but permission
    ;; denied is raised).
    (-> (render (slurp (io/resource "error.html")) request)
        (assoc :status 403))

    ;; Else, redirect it to login with link of current url
    ;; for post login redirect user to current url.
    (let [current-url (:uri request)]
      (redirect (format "/login?next=%s" current-url)))))

(defn -main
  [& args]
  (let [;; Create new backend overwriting the default exception
        ;; handler for authorization handler.
        backend (session-backend :unauthorized-handler unauthorized-handler)

        ;; Wrap a routers handler with some middlewares
        ;; such as authorization, authentication, params
        ;; and session.
        app     (-> app
                    (wrap-authorization backend)
                    (wrap-authentication backend)
                    (wrap-params)
                    (wrap-session))]

    ;; Use jetty adapter for run this example.
    (println "Now listening on: http://127.0.0.1:9090/")
    (jetty/run-jetty app {:port 9090})))
