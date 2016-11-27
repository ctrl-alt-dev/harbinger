# Harbinger

A Spring [MVC](http://projects.spring.io/spring-framework/)/[Security](http://projects.spring.io/spring-security/) based Web Application Intrusion Detection and Defense Framework.

> And even the like precurse of feared events, As harbingers preceding still the fates And prologue to the omen coming on, Have heaven and earth together demonstrated Unto our climatures and countrymen. -- Hamlet, Shakespeare

Harbinger detects suspicious activity in your web application and acts upon it. How and when can be defined by you.
It is intended for securing standalone spring based web applications. No cloud or infrastructure required.
Add a dependency, do some configuration, maybe add some validation hooks and you're done.  

# Features

* Detections
  * HTTP Request and Response
  * Servlet request parameters
  * Bean Validation / JSR-303 support
  * Exceptions
* Responses
  * None
  * Reject Input
  * Invalidate Session
  * Temporarily Blacklist IP 
* Other
  * White List for IPs, URLs, Users and Request Parameters
  * Customizable Detection Rules    

# Getting Started

## 1) Include Harbinger in your dependencies.

(when it is released, for now, build it from source :-)

```xml
        <dependency>
            <groupId>nl.ctrlaltdev.harbinger</groupId>
            <artifactId>harbinger</artifactId>
            <version>1.0.0</version>
        </dependency>
```

## 2) Configure Harbinger Beans

```java
    @Bean
    public HarbingerContext harbingerContext() {
        EvidenceCollector collector = new EvidenceCollector();
        ResponseDecider decider = new SimpleResponseDecider(collector);
        Set<DetectionRule> rules = new DetectionRuleLoader().load();
        return new DefaultHarbingerContext(rules, collector, decider);
    }
    
    @Bean
    public BlacklistFilter blacklistFilter(HarbingerContext ctx) {
        return new BlacklistFilter(ctx);
    }
    
    @Bean
    public HttpEvidenceFilter httpEvidenceFilter(HarbingerContext ctx) {
        return new HttpEvidenceFilter(ctx);
    }
```

## 3) Hook Filters into the Spring Security Chain

```java
        protected void configure(HttpSecurity http) throws Exception {
            http
                // etc
                .addFilterBefore(httpEvidenceFilter, ExceptionTranslationFilter.class) 
                .addFilterBefore(blacklistFilter, ChannelProcessingFilter.class)
                // etc
```

## Next steps

* Use the `@Tripwired` annotation to detect potentially malicious input on `@Valid` Forms or DTOs.
* Implement your own `ResponseDecider`.
* Add a `WhiteList` to the `EvidenceCollector` to suppress False Positives.
* Write your own Detection Rules.

# Conceptual Model

```
Detections -> Evidence -> Evidence Collector -> Evidence Aggregation ->  Response Decider -> Response Action
                                  ^
                                  |
                             White List
```

A Detection triggers on a certain event, such as an incoming HTTP Request or JSR 303 validation and produces Evidence.
Evidence may be enriched (for example with the current user, session id or remote IP) before its passed to the Evidence Collector.
The Evidence Collector logs and groups the evidence by session and IP and aggregates the result, producing an Evidence Aggregation.

This Aggregation is then fed into the Response Decider to determine the Response Action, which may be a rejection of the input, invalidation of the session, temporarily blacklisting of the IP or simply nothing. 

Sometimes False Positives may trigger an unwanted Response Action from Harbinger. 
In these cases you use the White List to let the Evidence Collector ignore any Evidence that matches certain characteristics.
The White List supports suppressing evidence based on IP address, URL, parameter name and user. Also it supports the boolean OR and AND operators.   

# Alternatives

* [ModSecurity](https://www.modsecurity.org/) - Open Source Web Application Firewall (for Apache Web Server)

* [OWASP App Sensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project) - Build self-defending applications through real-time event detection and response.

* [Bit Sensor](https://bitsensor.io/) - BitSensor uses big data correlation and efficient attack detection to create applications that defend themselves (commercial).

# License

[Apache 2](http://www.apache.org/licenses/LICENSE-2.0)

# Releases

None Yet!
	