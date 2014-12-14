(ns buddy.auth.accessrules
  (:require [buddy.auth :refer [throw-unauthorized]]
            [ring.util.response :as ring]
            [clojure.walk :refer [postwalk]]
            [clout.core :as clout]))

(defprotocol IRuleHandlerResponse
  (success? [_] "Check if a response is a success.")
  (get-value [_] "Get a hander response value."))

(deftype RuleSuccess [v]
  IRuleHandlerResponse
  (success? [_] true)
  (get-value [_] v)

  Object
  (equals [self other]
    (if (instance? RuleSuccess other)
      (= v (.-v other))
      false))

  (toString [self]
    (with-out-str (print [v]))))

(deftype RuleError [v]
  IRuleHandlerResponse
  (success? [_] false)
  (get-value [_] v)

  Object
  (equals [self other]
    (if (instance? RuleError other)
      (= v (.-v other))
      false))

  (toString [self]
    (with-out-str (print [v]))))


(defn success
  "Function that return a success state
  from one access rule handler."
  ([] (RuleSuccess. nil))
  ([v] (RuleSuccess. v)))

(defn error
  "Function that return a failure state
  from one access rule handler."
  ([] (RuleError. nil))
  ([v] (RuleError. v)))

(extend-protocol IRuleHandlerResponse
  nil
  (success? [_] false)
  (get-value [_] nil)

  Boolean
  (success? [v] v)
  (get-value [_] nil))

(defn compile-rule-handler
  "Receives a rule handler and return a compiled version of it.

  The compiled version of rule handler consists in
  one function that accepts a request as first parameter
  and return the result of the evaluation of it.

  The rule can be a simple function or logical expersion. Logical
  expresion is expressed using a hashmap:

     {:or [f1 f2]}
     {:and [f1 f2]}

  Logical expressions can be nestest as deep as you want:

     {:or [f1 {:and [f2 f3]}]}

  The rule handler as unit of work, should return a
  `success` or `error`. `success` is a simple mark that
  means that handler passes the validation and `error`
  is a mark that means that rule does not pass the
  validation.

  An error mark can return a ring response that will be
  returned to the http client or string message that will
  passed to `on-error` handler if it exists, or returned as
  bad-request response with message as response body.

  Example of success marks:
    true
    (success)

  Example of error marks:
    nil
    false
    (error \"Error msg\")
    (error {:status 400 :body \"Unauthorized\"})
  "
  [rule]
  (postwalk (fn [form]
              (cond
               ;; In this case is a handler
               (fn? form)
               (fn [req] (form req))

               (:or form)
               (fn [req]
                 (let [rules (:or form)
                       evals (map (fn [x] (x req)) rules)
                       accepts (filter success? evals)]
                   (if (seq accepts)
                     (first accepts)
                     (first evals))))

               (:and form)
               (fn [req]
                 (let [rules (:and form)
                       evals (map (fn [x] (x req)) rules)
                       rejects (filter (complement success?) evals)]
                   (if (seq rejects)
                     (first rejects)
                     (first evals))))

               :else form))
            rule))


(defn- compile-access-rule
  "Receives a access rule and return a compiled version of it.

  The plain version of access rule consists in one hash-map with
  with `:uri` and `:handler` keys. `:uri` is a url match syntax
  that will be used for match the url and `:handler` is a rule
  handler.

  Little overview of aspect of one access rule:

    [{:uri \"/foo\"
      :handler user-access}

  The clout library (https://github.com/weavejester/clout)
  for matching the `:uri`.

  It also has support for more advanced matching using
  plain regular expressions:

    [{:pattern #\"^/foo$\"
      :handler user-access}

  The compilation process consists in transform the plain version
  in one optimized of it for avoid unnecesary overhead to the
  request process time.

  The compiled version of access rule has very similar format that
  the plain one. The difference is that `:handler` is a compiled
  version, and `:pattern` or `:uri` is replaced by matcher function.

  Little overview of aspect of compiled version of acces rule:

    [{:matcher #<accessrules$compile_access_rule$fn__13092$fn__13095...>
      :handler #<accessrules$compile_rule_handler$fn__14040$fn__14043...>
  "
  [accessrule]
  (let [handler (compile-rule-handler (:handler accessrule))
        matcher (cond
                 (:pattern accessrule)
                 (fn [request]
                   (let [pattern (:pattern accessrule)
                         uri (:uri request)]
                     (boolean (seq (re-matches pattern uri)))))

                 (:uri accessrule)
                 (let [route (clout/route-compile (:uri accessrule))]
                   (fn [request]
                     (boolean (clout/route-matches route request))))

                 :else (fn [request] true))]
    (assoc accessrule
      :matcher matcher
      :handler handler)))

(defn- compile-access-rules
  "Compile a list of access rules.

  For more information, see the docstring
  of `compile-access-rule` function."
  [accessrules]
  (mapv compile-access-rule accessrules))

(defn- match-access-rules
  "Iterates over all rules and try match each one
  in order. Return a first matched rule or nil."
  [accessrules request]
  (first (filter (fn [accessrule]
                   (let [matcher (:matcher accessrule)]
                     (matcher request)))
                 accessrules)))

(defn- handle-error
  [rsp request {:keys [reject-handler on-error redirect]}]
  (let [val (get-value rsp)]
    (cond
     (ring/response? val)
     val

     (string? redirect)
     (ring/redirect redirect)

     (fn? on-error)
     (on-error request val)

     (fn? reject-handler)
     (reject-handler request val)

     (string? val)
     (-> (ring/response val)
         (ring/status 400))

     :else
     (throw-unauthorized))))

(defn apply-match-rule
  [match request]
  (let [handler (:handler match)]
    (handler request)))

(defn wrap-access-rules
  "An ring middleware that helps define access rules for
  ring handler.

  This is a example of access rules list that `wrap-access-rules`
  middleware expects:

      [{:uri \"/foo/*\"
        :handler user-access}
       {:uri \"/bar/*\"
        :handler {:or [user-access admin-access]}}
       {:uri \"/baz/*\"
        :handler {:and [user-access {:or [admin-access operator-access]}]}}]

  All access rules are evaluated in order and stops on first
  match found.

  See docstring of `compile-rule-handler` for documentation
  about rule handlers."
  [handler & [{:keys [policy rules] :or {policy :allow} :as opts}]]
  (when (nil? rules)
    (throw (IllegalArgumentException. "rules should not be empty.")))
  (let [accessrules (compile-access-rules rules)]
    (fn [request]
      (if-let [match (match-access-rules accessrules request)]
        (let [res (apply-match-rule match request)]
          (if (success? res)
           (handler request)
           (handle-error res request (merge opts match))))
        (case policy
          :allow (handler request)
          :reject (handle-error (error nil) request opts))))))

(defn restrict
  "Like `wrap-access-rules` middleware but works as
  decorator. Is intended for use with compojure routing
  library or similar. Example:

    (defn login-ctrl [req] ...)
    (defn admin-ctrl [req] ...)

    (defroutes app
      (ANY \"/login\" [] login-ctrl)
      (GET \"/admin\" [] (restrict admin-ctrl {:handler admin-access ;; Mandatory
                                               :on-error my-reject-handler)

  This decorator allow use same access rules but without
  any url matching algorithm but with disadvantage of
  accoupling your routers code with access rules."
  [handler rule]
  (let [match (compile-access-rule rule)]
    (fn [request]
      (let [rsp (apply-match-rule match request)]
        (if (success? rsp)
         (handler request)
         (handle-error rsp request rule))))))
