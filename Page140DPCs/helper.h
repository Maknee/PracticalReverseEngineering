#pragma once

#define PROJECT_NAME "Page140DPCs: "

#define Print(...)                                                             \
  do {                                                                         \
    DbgPrint(PROJECT_NAME __VA_ARGS__);                                        \
  } while (0)

#define PrintFunction()                                                        \
  do {                                                                         \
    DbgPrint(PROJECT_NAME "%s\n", __FUNCSIG__);                                \
  } while (0)

#define DbgPrintLine(...)                                                      \
  do {                                                                         \
    DbgPrint(PROJECT_NAME "%s %d: %s\n", __FILE__, __LINE__, __VA_ARGS__);     \
  } while (0)

#define DbgPrintFailure(status, ...)                                           \
  do {                                                                         \
    DbgPrintLine(__VA_ARGS__);                                                 \
    return status;                                                             \
  } while (0)
