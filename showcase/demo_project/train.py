import torch

def train(model, loader, opt, loss_fn):
    for x, y in loader:
        opt.zero_grad()
        loss = loss_fn(model(x.cuda()), y.cuda())
        loss.backward()
        opt.step()
        print(loss.item())
