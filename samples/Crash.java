
public class Crash
{
  private Crash() { }

  native static void forceSegfault();

  static
  {
    System.loadLibrary("crash");
  }
}

