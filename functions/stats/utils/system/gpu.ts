import si from 'systeminformation';
import { Graphics } from '@server/types/statistics/system';

export default async function getGPUInfo(): Promise<Graphics[]> {
    const graphics = await si.graphics();
    
    // Ensure we have at least one controller with default values if none are found
    const controllers = graphics.controllers.length > 0 
        ? graphics.controllers.map(controller => ({
            vendor: controller.vendor || '',
            model: controller.model || '',
            bus: controller.bus || '',
            vram: controller.vram ?? 0,
            vramDynamic: controller.vramDynamic ?? false
        }))
        : [{
            vendor: '',
            model: 'No GPU detected',
            bus: '',
            vram: 0,
            vramDynamic: false
        }];

    return [{
        controllers: controllers
    }];
}