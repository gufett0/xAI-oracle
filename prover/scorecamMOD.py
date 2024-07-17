import torch
import torch.nn.functional as F
import torch.nn as nn


#####–––––#######

class GetActivations(nn.Module):
    def __init__(self, model, target_layer):
        super(GetActivations, self).__init__()
        self.model = model
        self.target_layer = target_layer
        self.activations = []
        self.hook_layers()
        
    def hook_layers(self):
        def hook_function(module, input, output):
            self.activations.append(output)
        self.target_layer.register_forward_hook(hook_function)
        
    def forward(self, img1, img2):
        self.activations = []
        self.model.zero_grad()
        _ = self.model(img1, img2)
        return self.activations[0]

class GetMask(nn.Module):
    def __init__(self, activations):
        super(GetMask, self).__init__()
        self.activations = activations

    def forward(self, img1, index):
        saliency_map = self.activations[:, index, :, :].unsqueeze(1)
        normed_map = (saliency_map - saliency_map.min()) / (saliency_map.max() - saliency_map.min())
        masked_input = img1 * normed_map
        return masked_input
    
    
class GetScore(nn.Module):
    def __init__(self, model):
        super(GetScore, self).__init__()
        self.model = model

    def forward(self, masked_input, img2):
        score = self.model(masked_input, img2)
        return score

class GetCAM(nn.Module):
    def __init__(self, channels):
        super(GetCAM, self).__init__()
        self.channels = channels

    def forward(self, all_scores, activations):
        # Perform softmax
        weights = F.softmax(all_scores, dim=1)  # Shape: [batch_size, 8, 1]

        # Unsqueeze the softmax output to match the dimensions of activations
        #channels = activations.size(1)
        unsqueezed_corrected = weights.view(-1, self.channels, 1, 1)  

        # Perform the multiplication
        cam = unsqueezed_corrected * activations  
        cam = cam.sum(dim=1).squeeze()
        cam = F.relu(cam)
        cam = cam - cam.min()
        cam = cam / cam.max()
        return cam    