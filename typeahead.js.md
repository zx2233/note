### 自动补齐插件

```js
    var loadRequestMapping = function () {
        $.getJSON(BASE_URL + "/mgmt/permission/maps", null, function (resp) {
            var data = [];
            $(resp.data).each(function (index, item) {
                data.push(item.text);
            })
            $('#d_search_res').typeahead({
                    hint: true,
                    highlight: true,
                    minLength: 1
                },
                {
                    name: 'resources',
                    displayKey: 'value',
                    source: substringMatcher(resp.data)
                }).on('typeahead:selected', function (e, datum) {
                alert(datum.id)
            })
        })
    };
```



```js
/* 加载角色的权限信息*/
var substringMatcher = function (strs) {
    return function findMatches(q, cb) {
        var matches, substringRegex;
        matches = [];
        substrRegex = new RegExp(q, 'i');
        $.each(strs, function (i, str) {
            console.log(str)
            if (substrRegex.test(str.text)) {
                matches.push({id:str.id, value: str.text });
            }
        });
        cb(matches);
    };
};
```