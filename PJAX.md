# PJAX

http://bsify.admui.com/jquery-pjax/

pjax是一个jQuery插件，它通过ajax和pushState技术提供了极速的（无刷新ajax加载）浏览体验，并且保持了真实的地址、网页标题，浏览器的后退（前进）按钮也可以正常使用。

pjax的工作原理是通过ajax从服务器端获取HTML，在页面中用获取到的HTML替换指定容器元素中的内容。然后使用pushState技术更新浏览器地址栏中的当前地址。以下两点原因决定了pjax会有更快的浏览体验：

- 不存在页面资源（js/css）的重复加载和应用；
- 如果服务器端配置了pjax，它可以只渲染页面局部内容，从而避免服务器渲染完整布局的额外开销。



# PushState

