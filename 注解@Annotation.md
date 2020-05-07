# @Annotation

https://www.runoob.com/w3cnote/java-annotation.html

问题：其他注解如何继承 Annotation

 **@interface**

使用 @interface 定义注解时，意味着它实现了 java.lang.annotation.Annotation 接口，即该注解就是一个Annotation。

定义 Annotation 时，@interface 是必须的。

注意：它和我们通常的 implemented 实现接口的方法不同。Annotation 接口的实现细节都由编译器完成。通过 @interface 定义注解后，该注解不能继承其他的注解或接口。

## 定义

java中用@interface <className>{ } 定义一个注解 @Annotation，一个注解是一个类



## 作用

### 1、编译检查



### 2、在反射中使用 Annotation



### 3、根据 Annotation 生成帮助文档



###  4、能够帮忙查看查看代码