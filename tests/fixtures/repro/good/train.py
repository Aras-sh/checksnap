import json
import random
import subprocess
import sys

import numpy as np
import torch
from torch.utils.data import DataLoader

SEED = 0
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark = False
torch.use_deterministic_algorithms(True)
commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode()
json.dump({"seed": SEED, "commit": commit, **vars(sys.modules[__name__])}, open("config.json", "w"), default=str)
files = sorted(__import__("glob").glob("data/*.png"))
dl = DataLoader(files, shuffle=True, num_workers=4, generator=torch.Generator().manual_seed(SEED), worker_init_fn=lambda i: None)
