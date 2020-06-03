package learning.thread;

/**
 * @author xuan
 * @date 2020/5/18 10:56
 */

public class Test implements Runnable {
    protected int countDown=10;
    private static int taskCount=0;
    private final int id=taskCount++;
    public Test(){

    }
    public Test(int countDown){
        this.countDown=countDown;
    }
    private String status(){
        return id+":"+(countDown>0 ? countDown : "end");
    }
    @Override
    public void run() {
        while (countDown-->0){
            System.out.println(status());
            Thread.yield();
        }
    }
}
