# Mybatis plus - 映射字段时排除不必要的字段，忽略字段

1.transient关键字

2.使用静态变量(static)

3.TableField(exit=false)

### transient

Java语言的关键字，变量修饰符，如果用**transient**声明一个实例变量，当对象存储时，它的值不需要维持。换句话来说就是，用**transient**关键字标记的成员变量不参与序列化过程



### Mybatis中的like写法

```
LIKE CONCAT('%',#{name},'%')
```

```xml
    SELECT
        log.* ,
        manager.nickname
    FROM
        log,
        manager
        where log.user_id=manager.id
    <if test="logDTO.nickname != null ">
        and manager.nickname like "%"#{logDTO.nickname}"%"
    </if>
    <if test="logDTO.category != null ">
        and log.category like "%"#{logDTO.category}"%"
    </if>
    <if test="logDTO.timeStart != null ">
        and log.log_time <![CDATA[ >= ]]> #{logDTO.timeStart}
    </if>
    <if test="logDTO.timeEnd != null ">
        and log.log_time <![CDATA[ <= ]]> #{logDTO.timeEnd}
    </if>
        ORDER BY log.log_time DESC
```