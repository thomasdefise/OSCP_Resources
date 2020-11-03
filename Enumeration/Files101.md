### File analysis on Linux

1. file *file.extension*
The [file](https://man7.org/linux/man-pages/man1/file.1.html) command is used to determine the type of a file.
2. strings *file.extension*
The [strings](https://man7.org/linux/man-pages/man1/strings.1.html) command the sequences of printable characters in files


If finding know files like JQuery, .... do comparaison to see if stuff changed

#### Interesting file

|Extension|Attached program|how to analyse the content|
|-|---------- | ----------- |
|.bundle|Git|git clone *file.bundle*|
|.db|SQlite|sqlite3 *user.db*|