#!/bin/sh
echo '=== Declaring queues for CAPABILITY service ===';
        rabbitmqadmin declare queue name=tech_capability_queue durable=true;
        rabbitmqadmin declare queue name=business_capability_queue durable=true;
        rabbitmqadmin declare queue name=package_queue durable=true;
        rabbitmqadmin declare queue name=tc_description_quality durable=true;
        rabbitmqadmin declare queue name=bc_entry_in_sparx durable=true;
        rabbitmqadmin declare queue name=product_availability durable=true;
        rabbitmqadmin declare queue name=error_bc_entry_in_sparx durable=true;

        echo '=== Declaring queues for PRODUCTS service ===';
        rabbitmqadmin declare queue name=comparison_operations durable=true;
        rabbitmqadmin declare queue name=comparison_arch_operations durable=true;
        rabbitmqadmin declare queue name=delete_arch_container_relations durable=true;
        rabbitmqadmin declare queue name=delete_arch_interface_relations durable=true;
        rabbitmqadmin declare queue name=delete_arch_operation_relations durable=true;
        rabbitmqadmin declare queue name=update-product-owner-and-priority-by-cmdb durable=true;
        rabbitmqadmin declare queue name=delete_tc_to_operation durable=true;

        echo '✅ All queues declared successfully';