// temp name

#include "module.h"

LROT_BEGIN(capture, NULL, 0)
  // LROT_FUNCENTRY( manual, enduser_setup_manual )
  // LROT_FUNCENTRY( start, enduser_setup_start )
  // LROT_FUNCENTRY( stop, enduser_setup_stop )
LROT_END(capture, NULL, 0)


NODEMCU_MODULE(CAPTURE, "capture", capture, NULL);