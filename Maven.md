### 运行JAR包 提示没有主清单属性解决办法

一般遇见这种问题是因为JAR包中的META-INF文件夹下的MANIFEST.MF文件缺少定义jar接口类。就是缺少默认运行的Main类。

https://my.oschina.net/u/3523885/blog/1557350

一种情况是，springboot项目打包过程总，没有加入下面的插件，导致打包之后的数据缺少默认运行的Main类。

```xml
<build>
   <plugins>
	<plugin>
	    <groupId>org.springframework.boot</groupId>
	    <artifactId>spring-boot-maven-plugin</artifactId>
	</plugin>
    </plugins>
</build>
```

