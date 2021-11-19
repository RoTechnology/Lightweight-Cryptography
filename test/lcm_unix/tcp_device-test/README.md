# **Test Procedure for Tcp Device Communication**

===========================================

* **COMPILE PROCEDURE**

1. If needed, change the ip address at line 82 in **client.c**; default is _127.0.0.1_.

2. To compile the server, run the command:
    ```
    gcc server.c -o server
    ```

3. To compile the client, run the command:
    ```
    gcc client.c -o client
    ```


---

* **TEST PROCEDURE**

1. Run the **server** first, then run the **client**.

2. Client will prompt for an input string to encrypt and decrypt.

3. To terminate both client and server, input  "_exit_" in Client prompt.

===========================================