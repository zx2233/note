Shiro内置Cache缓存方案

https://www.cnblogs.com/nuccch/p/8044226.html

Shiro通过CacheManager组件实现权限数据缓存。当权限信息存放在数据库中时，对于每次前端的访问请求都需要进行一次数据库查询。特别是在大量使用shiro的jsp标签的场景下，对应前端的一个页面访问请求会同时出现很多的权限查询操作，这对于权限信息变化不是很频繁的场景，每次前端页面访问都进行大量的权限数据库查询是非常不经济的。因此，非常有必要对权限数据使用缓存方案。