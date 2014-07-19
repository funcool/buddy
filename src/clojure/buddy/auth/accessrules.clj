(ns buddy.auth.accessrules
  (:require [buddy.auth :refer [throw-unauthorized]]))

(defn compile-rule
  "Receives a rule handler and return one callable that
  can return true or false.
  The handler can be a simple symbol:

    my-function

  Or logicaly combined hash-map:

    {:or [my-func1 my-func2]}
    {:and [my-func1 my-func2]}

  Also, logic combinators can be nested:

    {:or [my-func1 {:and [myfn3 myfn4]}]}
  "
  [handler]
  (if (map? handler)
    (cond
      (:or handler) (fn [req]
                      (->> (map compile-rule (:or handler))
                           (map (fn [h] (boolean (h req))))
                           (some true?)
                           (boolean)))
      (:and handler) (fn [req]
                       (->> (map compile-rule (:and handler))
                            (map (fn [h] (boolean (h req))))
                            (every? true?)
                            (boolean)))
      :else (throw (RuntimeException. "Invalid rule format")))
    (fn [req] (boolean (handler req)))))

(defn match-rules
  "Iterates over all rules and try match each one
  in order. Return a first matched rule or nil.
  This function is used by RegexAccessRules class."
  [request rules]
  (let [filterfn (fn [rule] (seq (re-matches (:pattern rule) (:uri request))))]
    (first (filter filterfn rules))))

(defn apply-rule
  [request rule]
  "Compiles a rule and execute the rule handlers tree.
  If result a boolean value: true for grant access and
  false for deny."
  (let [rulehandler (compile-rule (:handler rule))]
    (rulehandler request)))

(defn restrict
  "Like `wrap-access-rules` middleware but works as
  decorator. Is intended for use with compojure routing
  library or similar. Example:

    (defn login-ctrl [req] ...)
    (defn admin-ctrl [req] ...)

    (defroutes app
      (ANY \"/login\" [] login-ctrl)
      (GET \"/admin\" [] (restrict admin-ctrl {:rule admin-access ;; Mandatory
                                               :reject-handler my-reject-handler)

  This decorator allow use same access rules but without
  any url matching algorithm but with disadvantage of
  accoupling your routers code with access rules.
  "
  [handler & [{:keys [rule reject-handler]}]]
  (fn [request]
    (if (apply-rule request {:handler rule})
      (handler request)
      (if reject-handler
        (reject-handler request)
        (if-let [reject-handler (get-in request [:access-rules :reject-handler])]
          (reject-handler request)
          (throw-unauthorized))))))
