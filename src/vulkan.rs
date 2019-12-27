use std::borrow::Cow;
use std::sync::Arc;
use vulkano::instance as vulkan;
use vulkano::device;
use vulkano::buffer;
use vulkano::command_buffer;
use vulkano::command_buffer::CommandBuffer;
use vulkano::pipeline;
use vulkano::descriptor::descriptor_set;
use vulkano::sync::GpuFuture;
use vulkano::format::Format;
use vulkano::image::Dimensions;
use vulkano::image::StorageImage;
use png;

mod cs {
    vulkano_shaders::shader!{
        ty: "compute",
        src: "#version 450

              layout(local_size_x = 8, local_size_y = 8, local_size_z = 1) in;

              layout(set = 0, binding = 0, rgba8) uniform writeonly image2D img;

              void main() {
                  vec2 norm_coordinates = (gl_GlobalInvocationID.xy + vec2(0.5)) / vec2(imageSize(img));
                  vec2 c = (norm_coordinates - vec2(0.5)) * 2.0 - vec2(1.0, 0.0);

                  vec2 z = vec2(0.0, 0.0);
                  float i;
                  for (i = 0.0; i < 1.0; i += 0.005) {
                      z = vec2(
                          z.x * z.x - z.y * z.y + c.x,
                          z.y * z.x + z.x * z.y + c.y
                      );

                      if (length(z) > 4.0) {
                          break;
                      }
                  }

                  vec4 to_write = vec4(vec3(i), 1.0);
                  imageStore(img, ivec2(gl_GlobalInvocationID.xy), to_write);
              }"
    }
}

pub fn make_fractal_image(width: u32, height: u32) -> Vec<u8> {
    let app_info = vulkan::ApplicationInfo {
        application_name: Some(Cow::Borrowed("vulnode")),
        application_version: Some(vulkan::Version{major:0, minor:0, patch:1}),
        engine_name: Some(Cow::Borrowed("vulnode")),
        engine_version: Some(vulkan::Version{major:0, minor:0, patch:1}),
    };

    let instance = vulkan::Instance::new(Some(&app_info), &vulkan::InstanceExtensions::none(), None)
                            .expect("failed to create instance");
    
    let physical = vulkan::PhysicalDevice::enumerate(&instance).next().expect("can not find device onboard!");

    let queue_family = physical.queue_families()
                               .find(|&q| q.supports_compute())
                               .expect("couldn't find a compute queue family");

    let (device, mut queues) = device::Device::new(physical,
                                                   &device::Features::none(),
                                                   &device::DeviceExtensions::supported_by_device(physical),
                                                   [(queue_family, 0.5)].iter().cloned()
                                                  )
                               .expect("failed to create device");
    
    let queue = queues.next().unwrap();

    let image = StorageImage::new(device.clone(), Dimensions::Dim2d{width, height},
                              Format::R8G8B8A8Unorm, Some(queue.family())).unwrap();

    let shader = cs::Shader::load(device.clone()).expect("failed to create shader module");

    let compute_pipeline = Arc::new(
        pipeline::ComputePipeline::new(device.clone(), &shader.main_entry_point(), &()
    ).expect("failed to create compute pipeline"));

    let set = Arc::new(
        descriptor_set::PersistentDescriptorSet::start(compute_pipeline.clone(), 0)
            .add_image(image.clone()).unwrap()
            .build().unwrap()
    );

    let buf = buffer::CpuAccessibleBuffer::from_iter(
        device.clone(),
        buffer::BufferUsage::all(),
        (0 .. width * height * 4).map(|_| 0u8)
    ).expect("failed to create buffer");

    let command_buffer = command_buffer::AutoCommandBufferBuilder::new(device.clone(), queue.family()).unwrap()
        .dispatch([width / 8, height / 8, 1], compute_pipeline.clone(), set.clone(), ()).unwrap()
        .copy_image_to_buffer(image.clone(), buf.clone()).unwrap()
        .build().unwrap();

    let finished = command_buffer.execute(queue.clone()).unwrap();

    finished.then_signal_fence_and_flush().unwrap()
        .wait(None).unwrap();

    let buffer_content = buf.read().unwrap();
    let mut image_data = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut image_data, width, height);
        encoder.set_color(png::ColorType::RGBA);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().unwrap();

        writer.write_image_data(&buffer_content[..]).unwrap();
    }

    image_data
}
