f = open('/secrets/random_seed','rb').read()
open('/secrets/broadcast_key','wb').write(f[:16])

