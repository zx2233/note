# Git

<>:表示语句中必须指定的数据对象。 []:表明可选可不选。 |：表示多个选项只能选一个。

(-p|--patch) ，()括号内表示命令作用相同



### Untracked files: 未被追踪文件

- 新文件，未被add

### Changes not staged for commit:  未提交的更改:

- 文件已被add,成为被追踪文件tracked files
- 被追踪文件此时相对于之前，已被修改

### HEAD

当前你所操作的分支或提交记录

### Index

index也被称为staging area(暂存区)，是指一整套即将被下一个提交的文件集合。他也是将成为HEAD的父亲的那个commit

### Working Copy

working copy代表你正在工作的那个文件集

### 分离HEAD

​		HEAD 是一个对当前检出记录的符号引用 —— 也就是指向你正在其基础上进行工作的提交记录。

​		HEAD 总是指向当前分支上最近一次提交记录。大多数修改提交树的 Git 命令都是从改变 HEAD 的指向开始的。

​		HEAD 通常情况下是指向分支名的

​		**分离的head**就是让其指向某个具体的**提交记录**而不是**分支名**



### checkout

​		head->branch->index->work tree

​		branch(分支)可以理解为一个指针，一般是指向当前分支的最新commit

​		git checkout <分支|提交记录> 	

​		当**切换分支或之前的提交记录**时，因为 要切换的分支或提交记录的index(暂存区)和work tree（工作目录）状态一致[已经add ,commit,且没有其他修改]，切换即是连同 head，index，work tree，一同切换到所切换分支或记录的状态。

​		git checkout --<file>：将index（暂存区的文件）覆盖工作区的文件。

#### 移动head或分支位置

##### 相对引用

git checkout head^

head位置向上移动一个提交记录

git checkout head~4

head位置向上移动四个提交记录

git checkout master~4

master位置向上移动四个提交记录

- 使用 `^` 向上移动 1 个提交记录
- 使用 `~<num>` 向上移动多个提交记录，如 `~4`

#### 强制修改分支位置

`-f` 选项让分支指向另一个提交

git branch -f master <提交记录>

### reflog

​		每一次本地的commit都会生成快照，并且生成日志记录。当你进行reset等回退操作，被回退的记录依旧存在，使用reflog可以查看和 切换到被回退的提交记录





reflog不是永久保存的，有一个可配置的过期时间，reflog中过期的信息会被自动删除。



### reset

https://www.cnblogs.com/kidsitcn/p/4513297.html

​		当你add之后，想撤销当前add的内容，并且工作区没有修改，使用 

- git reset head

- git checkout <你add的内容>

  或者

- git reset --hard head



reset后，被回退的提交记录所做的变更还在，但是处于未加入暂存区状态。

#### soft

--soft参数告诉Git重置HEAD到另外一个commit，但也到此为止。如果你指定--soft参数，Git将停止在那里而什么也不会根本变化。这意味着index,working copy都不会做任何变化，所有的在original HEAD和你重置到的那个commit之间的所有变更集都放在stage(index)区域中。

#### hard

-hard参数将会blow out everything.它将重置HEAD返回到另外一个commit(取决于~12的参数），重置index以便反映HEAD的变化，并且重置working copy也使得其完全匹配起来。这是一个比较危险的动作，具有破坏性，数据因此可能会丢失！如果真是发生了数据丢失又希望找回来，那么只有使用：git reflog命令了。makes everything match the commit you have reset to.你的所有本地修改将丢失。如果我们希望彻底丢掉本地修改但是又不希望更改branch所指向的commit，则执行git reset --hard = git reset --hard HEAD. i.e. don't change the branch but get rid of all local changes.另外一个场景是简单地移动branch从一个到另一个commit而保持index/work区域同步。这将确实令你丢失你的工作，因为它将修改你的work tree！

#### mixed（默认）

--mixed是reset的默认参数，也就是当你不指定任何参数时的参数。它将重置HEAD到另外一个commit,并且重置index以便和HEAD相匹配，但是也到此为止。working copy不会被更改。所有该branch上从original HEAD（commit）到你重置到的那个commit之间的所有变更将作为local modifications保存在working area中，（被标示为local modification or untracked via git status)，但是并未staged的状态，你可以重新检视然后再做修改和commit



### cherry-pick 整理提交记录

把另一个分支的一个或多个提交复制到当前分支



### rebase 

 git rebase

Rebase 实际上就是取出一系列的提交记录，“复制”它们，然后在另外一个地方逐个的放下去。

Rebase 的优势就是可以创造更线性的提交历史，这听上去有些难以理解。如果只允许使用 Rebase 的话，代码库的提交历史将会变得异常清晰。

#### 交互式rebase

 git rebase -i



### git commit   --amend      

撤销上一次提交  并讲暂存区文件重新提交



**discard changes 放弃更改**

若对仓库权限有更加严格的要求，建议使用SVN。