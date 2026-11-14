#pragma once

void profile_start(void);
void profile_stop(void);

#if defined(PROFILE) && defined(DEVMODE)
#define PROFILE_START profile_start
#define PROFILE_STOP profile_stop
#else
#define PROFILE_START() do{}while(0)
#define PROFILE_STOP() do{}while(0)
#endif
