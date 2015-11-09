Invoker defender
================

invoker-defender is a Java Agent designed as a mitigation effort against deserialization attacks.

See http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ for details on this attack.

> PLEASE NOTE: invoker-defender only does what it does. It does not fix the problem with deserialization attacks. It only knowns about some well known classes which it makes unserializable. It cannot protect you from deserializing other vulnerable classes.

## How?
 
invoker-defender makes some well known vulnerable classes non-serializable by rewriting their byte code when the class loads.

Trying to deserialize to a non-serializable class will result in an InvalidClassException.

## Usage

Build invoker-defender:

    mvn clean install

This builds an invoker-defender jar file in target/invoker-defender-1.0-SNAPSHOT.jar

Copy this as invoker-defender.jar to your application, and add the following parameters to your Java startup script:

    -javaagent:invoker-defender.jar

## Which classes are unserialized?

By default, invoker-defender unserializes the following classes:

* org.apache.commons.collections.functors.InvokerTransformer
* org.apache.commons.collections4.functors.InvokerTransformer
* org.codehaus.groovy.runtime.ConvertedClosure
* com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl

You can add your own classes to this list by passing a comma-separated list of classes as a system property:

    -javaagent:invoker-defender.jar -Dinvoker.defender.custom.classes=com.example.Car,com.example.Wheel,com.example.Door


## Whitelisting mode

As always, it would be better if we could accept only classes we explicitly want to allow for deserialization. Rejecting based on a whitelist is better security than rejecting based on a blacklist.

To help build a whitelist file with legitimately serializable classes, a 'dryrun' option has been added. Together with an empty white list, this will create a list of classes which your application actually deserializes.

This can be produced by configuring the agent as follows:

    -javaagent:invoker-defender.jar -Dinvoker.defender.whitelist=empty.txt -Dinvoker.defender.dryrun=is-deserialized.txt

Where 'empty.txt' is an empty file and 'is-deserialized.txt' is a file where the names of your actually deserialized classes will be written to. 

After you are confident that all deserializable classes in your application have been recorded, you may restart your app, now reusing the recorded-as-serialized file as the whitelist:

    -javaagent:invoker-defender.jar -Dinvoker.defender.whitelist=is-deserialized.txt

## What happens when invoker-defender rejects a deserialization attempt?

An Exception will be thrown, looking something like this:

    java.lang.IllegalStateException: Deserialization not allowed for class java.util.concurrent.locks.AbstractOwnableSynchronizer
    	at org.kantega.invokerdefender.DefenderClassFileTransformer.preventDeserialization(DefenderClassFileTransformer.java:119)
