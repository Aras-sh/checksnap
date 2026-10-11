import glob
import random
from datetime import datetime

import numpy as np
import torch
from torch.utils.data import DataLoader

torch.backends.cudnn.benchmark = True
files = glob.glob("data/*.png")
tags = [t for t in set(f.split("/")[-1] for f in files)]
run_dir = f"runs/{datetime.now():%Y%m%d}"
x = random.random()
random.seed(0)
dl = DataLoader(files, shuffle=True, num_workers=4)
idx = torch.zeros(3).index_add_(0, torch.tensor([0, 1, 1]), torch.ones(3))
