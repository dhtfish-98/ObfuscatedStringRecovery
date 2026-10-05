/* Calls an unresolved symbol, forcing a relocation against executable .text. */
extern void outside_object(void);
void relocated_call(void) { outside_object(); }
