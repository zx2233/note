package learning.thread;

/**
 * @author xuan
 * @date 2020/5/28 13:42
 */
class TestA{
    public void d(){
        System.out.println("TestA");
    }
}
public class DualSynch {
    public void d(){
        System.out.println("DualSynch");
    }
    private Object object=new Object();
//    public  synchronized void f(){
//            for (int i = 0; i < 1000; i++) {
//                System.out.println("f()");
//                Thread.yield();
//            }
//    }
    public   void f(){
        synchronized(this){
            for (int i = 0; i < 1000; i++) {
                System.out.println("f()");
                Thread.yield();
            }
        }


    }

    public  void g(){
        synchronized (object){
            for (int i = 0; i < 1000; i++) {
                System.out.println("g()");
                Thread.yield();
            }
        }
    }

    public static void main(String[] args) throws InterruptedException {
       final DualSynch dualSynch=new DualSynch();
        new Thread(){
            @Override
            public void run() {
                dualSynch.g();
            }
        }.start();

        new Thread(){
            @Override
            public void run() {
                dualSynch.f();

            }
        }.start();

    }

}

